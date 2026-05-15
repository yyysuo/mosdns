package coremain

import (
	"container/heap"
	"container/list"
	"encoding/json"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// --- Optimized String Interning (Lock-Free) ---
const lruCacheSize = 16384

type lruEntry struct {
	key   string
	value string
}

// lruCache 已经移除了互斥锁，因为在优化后的设计中，它仅由单个 worker 协程调用
type lruCache struct {
	capacity int
	cache    map[string]*list.Element
	ll       *list.List
}

func newLRUCache(capacity int) *lruCache {
	if capacity <= 0 {
		capacity = lruCacheSize
	}
	return &lruCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element, capacity),
		ll:       list.New(),
	}
}

func (l *lruCache) Get(key string) (value string, ok bool) {
	if elem, hit := l.cache[key]; hit {
		l.ll.MoveToFront(elem)
		return elem.Value.(*lruEntry).value, true
	}
	return "", false
}

func (l *lruCache) Put(key, value string) {
	if elem, hit := l.cache[key]; hit {
		l.ll.MoveToFront(elem)
		elem.Value.(*lruEntry).value = value
		return
	}

	if l.ll.Len() >= l.capacity {
		oldest := l.ll.Back()
		if oldest != nil {
			l.ll.Remove(oldest)
			delete(l.cache, oldest.Value.(*lruEntry).key)
		}
	}

	elem := l.ll.PushFront(&lruEntry{key: key, value: value})
	l.cache[key] = elem
}

type auditContext struct {
	Ctx                *query_context.Context
	ProcessingDuration time.Duration
}

// Pool for auditContext to minimize GC overhead
var auditCtxPool = sync.Pool{
	New: func() any { return new(auditContext) },
}

type AnswerDetail struct {
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

type AuditLog struct {
	ClientIP      string         `json:"client_ip"`
	QueryType     string         `json:"query_type"`
	QueryName     string         `json:"query_name"`
	QueryClass    string         `json:"query_class"`
	QueryTime     time.Time      `json:"query_time"`
	DurationMs    float64        `json:"duration_ms"`
	TraceID       string         `json:"trace_id"`
	ResponseCode  string         `json:"response_code"`
	ResponseFlags ResponseFlags  `json:"response_flags"`
	Answers       []AnswerDetail `json:"answers"`
	DomainSet     string         `json:"domain_set,omitempty"`
}

type ResponseFlags struct {
	AA bool `json:"aa"`
	TC bool `json:"tc"`
	RA bool `json:"ra"`
}

const (
	defaultAuditCapacity   = 100000
	maxAuditCapacity       = 400000
	slowestQueriesCapacity = 300
	auditChannelCapacity   = 10240
	auditSettingsFilename  = "audit_settings.json"
)

type AuditSettings struct {
	Capacity int `json:"capacity"`
}

type slowestQueryHeap []AuditLog

func (h slowestQueryHeap) Len() int           { return len(h) }
func (h slowestQueryHeap) Less(i, j int) bool { return h[i].DurationMs < h[j].DurationMs }
func (h slowestQueryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *slowestQueryHeap) Push(x any) {
	*h = append(*h, x.(AuditLog))
}

func (h *slowestQueryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

type AuditCollector struct {
	mu                 sync.RWMutex
	capturing          atomic.Bool
	capacity           atomic.Int64
	logs               []AuditLog
	head               int
	slowestQueries     slowestQueryHeap
	domainCounts       map[string]int
	clientCounts       map[string]int
	domainSetCounts    map[string]int
	totalQueryDuration float64
	ctxChan            chan *auditContext
	quitChan           chan struct{}
	workerDone         chan struct{}

	stringLRU *lruCache // 实例级锁消除

	// Global Statistics for monitoring without mutex pressure
	totalQueryCountGlobal    atomic.Uint64
	totalQueryDurationGlobal atomic.Uint64 // Stored in microseconds
}

var GlobalAuditCollector = NewAuditCollector(defaultAuditCapacity)

func InitializeAuditCollector(configBaseDir string) {
	initialCapacity := defaultAuditCapacity
	settingsPath := filepath.Join(configBaseDir, auditSettingsFilename)
	settings := &AuditSettings{}
	data, err := os.ReadFile(settingsPath)

	if err == nil {
		if json.Unmarshal(data, settings) == nil {
			initialCapacity = settings.Capacity
			if initialCapacity < 0 {
				initialCapacity = 0
			}
			if initialCapacity > maxAuditCapacity {
				initialCapacity = maxAuditCapacity
			}
			mlog.S().Infof("Loaded audit log capacity: %d", initialCapacity)
		}
	}

	if initialCapacity != defaultAuditCapacity {
		GlobalAuditCollector = NewAuditCollector(initialCapacity)
	}
}

func NewAuditCollector(capacity int) *AuditCollector {
	c := &AuditCollector{
		logs:               make([]AuditLog, 0, capacity),
		slowestQueries:     make(slowestQueryHeap, 0, slowestQueriesCapacity),
		domainCounts:       make(map[string]int),
		clientCounts:       make(map[string]int),
		domainSetCounts:    make(map[string]int),
		totalQueryDuration: 0.0,
		ctxChan:            make(chan *auditContext, auditChannelCapacity),
		quitChan:           make(chan struct{}),
		workerDone:         make(chan struct{}),
		stringLRU:          newLRUCache(lruCacheSize),
	}
	c.capacity.Store(int64(capacity))
	c.capturing.Store(true)
	heap.Init(&c.slowestQueries)
	return c
}

func (c *AuditCollector) internString(s string) string {
	switch s {
	case "A", "AAAA", "CNAME", "TXT", "NS", "MX", "PTR", "SOA", "SRV", "HTTPS", "SVCB",
		"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "IN",
		"NO_RESPONSE", "unmatched_rule":
		return s
	}

	if val, ok := c.stringLRU.Get(s); ok {
		return val
	}
	c.stringLRU.Put(s, s)
	return s
}

func (c *AuditCollector) StartWorker() {
	go c.worker()
}

func (c *AuditCollector) StopWorker() {
	close(c.quitChan)
	<-c.workerDone
}

func (c *AuditCollector) worker() {
	defer close(c.workerDone)
	batch := make([]*auditContext, 0, 256)

	for {
		batch = batch[:0]

		select {
		case <-c.quitChan:
			return
		case wrappedCtx := <-c.ctxChan:
			batch = append(batch, wrappedCtx)
		}

		// Non-blocking drain to fill the batch
	drainLoop:
		for len(batch) < cap(batch) {
			select {
			case <-c.quitChan:
				break drainLoop // 快速逃逸并处理剩余 batch
			case nextItem := <-c.ctxChan:
				batch = append(batch, nextItem)
			default:
				break drainLoop
			}
		}

		c.processBatch(batch)

		for _, item := range batch {
			auditCtxPool.Put(item)
		}

		select {
		case <-c.quitChan:
			return
		default:
		}
	}
}

func (c *AuditCollector) processBatch(batch []*auditContext) {
	parsedLogs := make([]AuditLog, 0, len(batch))
	capVal := int(c.capacity.Load())

	// Step 1: 在无锁环境下进行结构组装、字符串解析、LRU 缓存等耗时操作
	for _, wrappedCtx := range batch {
		if wrappedCtx == nil || wrappedCtx.Ctx == nil {
			continue
		}

		qCtx := wrappedCtx.Ctx
		qQuestion := qCtx.QQuestion()
		duration := wrappedCtx.ProcessingDuration
		durationMs := float64(duration.Microseconds()) / 1000.0

		// Instant update of global atomic statistics
		c.totalQueryCountGlobal.Add(1)
		c.totalQueryDurationGlobal.Add(uint64(duration.Microseconds()))

		if !c.capturing.Load() || capVal == 0 {
			continue
		}

		clientAddr := qCtx.ServerMeta.ClientAddr.String()
		if host, _, err := net.SplitHostPort(clientAddr); err == nil {
			clientAddr = host
		}

		qName := qQuestion.Name
		if len(qName) > 1 && qName[len(qName)-1] == '.' {
			qName = qName[:len(qName)-1]
		}

		log := AuditLog{
			ClientIP:   c.internString(clientAddr),
			QueryType:  c.internString(dns.TypeToString[qQuestion.Qtype]),
			QueryName:  c.internString(qName),
			QueryClass: c.internString(dns.ClassToString[qQuestion.Qclass]),
			QueryTime:  qCtx.StartTime(),
			DurationMs: durationMs,
			TraceID:    qCtx.TraceID,
		}

		if val, ok := qCtx.GetValue(query_context.KeyDomainSet); ok {
			if name, isString := val.(string); isString {
				log.DomainSet = name
			}
		}

		if log.DomainSet == "" {
			log.DomainSet = "unmatched_rule"
		}

		if resp := qCtx.R(); resp != nil {
			log.ResponseCode = c.internString(dns.RcodeToString[resp.Rcode])
			log.ResponseFlags = ResponseFlags{
				AA: resp.Authoritative,
				TC: resp.Truncated,
				RA: resp.RecursionAvailable,
			}

			if len(resp.Answer) > 0 {
				log.Answers = make([]AnswerDetail, 0, len(resp.Answer))
				for _, ans := range resp.Answer {
					header := ans.Header()
					detail := AnswerDetail{
						Type: c.internString(dns.TypeToString[header.Rrtype]),
						TTL:  header.Ttl,
					}
					switch record := ans.(type) {
					case *dns.A:
						detail.Data = c.internString(record.A.String())
					case *dns.AAAA:
						detail.Data = c.internString(record.AAAA.String())
					case *dns.CNAME:
						detail.Data = c.internString(record.Target)
					case *dns.PTR:
						detail.Data = c.internString(record.Ptr)
					case *dns.NS:
						detail.Data = c.internString(record.Ns)
					case *dns.MX:
						detail.Data = c.internString(record.Mx)
					case *dns.TXT:
						detail.Data = c.internString(strings.Join(record.Txt, " "))
					default:
						detail.Data = c.internString(ans.String())
					}
					log.Answers = append(log.Answers, detail)
				}
			}
		} else {
			log.ResponseCode = "NO_RESPONSE"
		}
		parsedLogs = append(parsedLogs, log)
	}

	if len(parsedLogs) == 0 {
		return
	}

	// Step 2: 细粒度锁定，仅处理数组追加与增量状态更新，彻底消除耗时
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, log := range parsedLogs {
		if len(c.logs) == capVal {
			c.decrementStats(c.logs[c.head])
		}

		c.incrementStats(log)

		// Circular array logic
		if len(c.logs) < capVal {
			c.logs = append(c.logs, log)
		} else {
			c.logs[c.head] = log
			c.head = (c.head + 1) % capVal
		}

		// Update slowest queries heap
		if c.slowestQueries.Len() < slowestQueriesCapacity {
			heap.Push(&c.slowestQueries, log)
		} else if log.DurationMs > c.slowestQueries[0].DurationMs {
			c.slowestQueries[0] = log
			heap.Fix(&c.slowestQueries, 0)
		}
	}
}

// 增量统计函数（配合无全量大锁的设计）
func (c *AuditCollector) incrementStats(log AuditLog) {
	c.domainCounts[log.QueryName]++
	c.clientCounts[log.ClientIP]++
	c.domainSetCounts[log.DomainSet]++
	c.totalQueryDuration += log.DurationMs
}

func (c *AuditCollector) decrementStats(log AuditLog) {
	if c.domainCounts[log.QueryName] > 1 {
		c.domainCounts[log.QueryName]--
	} else {
		delete(c.domainCounts, log.QueryName)
	}

	if c.clientCounts[log.ClientIP] > 1 {
		c.clientCounts[log.ClientIP]--
	} else {
		delete(c.clientCounts, log.ClientIP)
	}

	if c.domainSetCounts[log.DomainSet] > 1 {
		c.domainSetCounts[log.DomainSet]--
	} else {
		delete(c.domainSetCounts, log.DomainSet)
	}

	c.totalQueryDuration -= log.DurationMs
	if c.totalQueryDuration < 0 {
		c.totalQueryDuration = 0
	}
}

func (c *AuditCollector) Collect(qCtx *query_context.Context) {
	if !c.IsCapturing() {
		return
	}

	duration := time.Since(qCtx.StartTime())

	wrappedCtx := auditCtxPool.Get().(*auditContext)
	wrappedCtx.Ctx = qCtx
	wrappedCtx.ProcessingDuration = duration

	select {
	case c.ctxChan <- wrappedCtx:
	default:
		auditCtxPool.Put(wrappedCtx)
	}
}

func (c *AuditCollector) Start()            { c.capturing.Store(true) }
func (c *AuditCollector) Stop()             { c.capturing.Store(false) }
func (c *AuditCollector) IsCapturing() bool { return c.capturing.Load() }

func (c *AuditCollector) GetLogs() []AuditLog {
	c.mu.RLock()
	defer c.mu.RUnlock()

	capVal := int(c.capacity.Load())
	if capVal == 0 || len(c.logs) == 0 {
		return []AuditLog{}
	}

	if len(c.logs) < capVal {
		logsCopy := make([]AuditLog, len(c.logs))
		copy(logsCopy, c.logs)
		return logsCopy
	}

	logsCopy := make([]AuditLog, capVal)
	copy(logsCopy, c.logs[c.head:])
	copy(logsCopy[capVal-c.head:], c.logs[:c.head])
	return logsCopy
}

func (c *AuditCollector) ClearLogs() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.logs != nil {
		c.logs = c.logs[:0]
	}

	c.head = 0
	c.slowestQueries = make(slowestQueryHeap, 0, slowestQueriesCapacity)
	heap.Init(&c.slowestQueries)
	c.domainCounts = make(map[string]int)
	c.clientCounts = make(map[string]int)
	c.domainSetCounts = make(map[string]int)
	c.totalQueryDuration = 0.0
}

func (c *AuditCollector) GetCapacity() int {
	return int(c.capacity.Load())
}

func (c *AuditCollector) SetCapacity(newCapacity int, configBaseDir string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if newCapacity < 0 {
		newCapacity = 0
	}
	if newCapacity > maxAuditCapacity {
		newCapacity = maxAuditCapacity
	}

	c.saveSettings(newCapacity, configBaseDir)

	c.capacity.Store(int64(newCapacity))
	c.logs = make([]AuditLog, 0, newCapacity)
	c.head = 0
	c.slowestQueries = make(slowestQueryHeap, 0, slowestQueriesCapacity)
	heap.Init(&c.slowestQueries)
	c.domainCounts = make(map[string]int)
	c.clientCounts = make(map[string]int)
	c.domainSetCounts = make(map[string]int)
	c.totalQueryDuration = 0.0
}

func (c *AuditCollector) saveSettings(capacityToSave int, configBaseDir string) {
	settings := AuditSettings{Capacity: capacityToSave}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		mlog.L().Error("failed to marshal audit settings", zap.Error(err))
		return
	}
	settingsPath := filepath.Join(configBaseDir, auditSettingsFilename)
	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		mlog.L().Error("failed to write audit settings file", zap.String("path", settingsPath), zap.Error(err))
	} else {
		mlog.L().Info("successfully saved audit settings", zap.String("path", settingsPath), zap.Int("capacity", capacityToSave))
	}
}

type V2GetLogsParams struct {
	Page        int
	Limit       int
	Domain      string
	AnswerIP    string
	AnswerCNAME string
	ClientIP    string
	Q           string
	Exact       bool
}

func (c *AuditCollector) CalculateV2Stats() V2StatsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalQueryCount := uint64(len(c.logs))
	avgDuration := 0.0
	if totalQueryCount > 0 {
		avgDuration = c.totalQueryDuration / float64(totalQueryCount)
	}

	return V2StatsResponse{
		TotalQueries:      totalQueryCount,
		AverageDurationMs: avgDuration,
	}
}

type rankHeap []V2RankItem

func (h rankHeap) Len() int           { return len(h) }
func (h rankHeap) Less(i, j int) bool { return h[i].Count < h[j].Count }
func (h rankHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *rankHeap) Push(x any)        { *h = append(*h, x.(V2RankItem)) }
func (h *rankHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func (c *AuditCollector) getRankFromMap(sourceMap map[string]int, limit int) []V2RankItem {
	if len(sourceMap) == 0 {
		return []V2RankItem{}
	}

	if len(sourceMap) <= limit {
		res := make([]V2RankItem, 0, len(sourceMap))
		for k, v := range sourceMap {
			res = append(res, V2RankItem{Key: k, Count: v})
		}
		sort.Slice(res, func(i, j int) bool {
			return res[i].Count > res[j].Count
		})
		return res
	}

	h := &rankHeap{}
	heap.Init(h)

	for key, count := range sourceMap {
		if h.Len() < limit {
			heap.Push(h, V2RankItem{Key: key, Count: count})
		} else if count > (*h)[0].Count {
			heap.Pop(h)
			heap.Push(h, V2RankItem{Key: key, Count: count})
		}
	}

	result := make([]V2RankItem, h.Len())
	for i := h.Len() - 1; i >= 0; i-- {
		result[i] = heap.Pop(h).(V2RankItem)
	}

	return result
}

type RankType string

const (
	RankByDomain    RankType = "domain"
	RankByClient    RankType = "client"
	RankByDomainSet RankType = "domain_set"
)

func (c *AuditCollector) CalculateRank(rankType RankType, limit int) []V2RankItem {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch rankType {
	case RankByDomain:
		return c.getRankFromMap(c.domainCounts, limit)
	case RankByClient:
		return c.getRankFromMap(c.clientCounts, limit)
	case RankByDomainSet:
		return c.getRankFromMap(c.domainSetCounts, limit)
	default:
		return []V2RankItem{}
	}
}

func (c *AuditCollector) GetSlowestQueries(limit int) []AuditLog {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.slowestQueries.Len() == 0 {
		return []AuditLog{}
	}

	snapshot := make([]AuditLog, c.slowestQueries.Len())
	copy(snapshot, c.slowestQueries)

	sort.Slice(snapshot, func(i, j int) bool {
		return snapshot[i].DurationMs > snapshot[j].DurationMs
	})

	if len(snapshot) > limit {
		return snapshot[:limit]
	}
	return snapshot
}

// 零内存分配的极速 ASCII 忽略大小写匹配函数
func containsFold(s, substrLower string) bool {
	if len(substrLower) == 0 {
		return true
	}
	if len(s) < len(substrLower) {
		return false
	}

	hasNonASCII := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 128 {
			hasNonASCII = true
			break
		}
	}
	if hasNonASCII {
		return strings.Contains(strings.ToLower(s), substrLower)
	}

	for i := 0; i <= len(s)-len(substrLower); i++ {
		match := true
		for j := 0; j < len(substrLower); j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != substrLower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (c *AuditCollector) GetV2Logs(params V2GetLogsParams) V2PaginatedLogsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	capVal := int(c.capacity.Load())
	totalLogs := len(c.logs)
	if totalLogs == 0 || capVal == 0 {
		return V2PaginatedLogsResponse{
			Pagination: V2PaginationInfo{CurrentPage: params.Page, ItemsPerPage: params.Limit},
			Logs:       []AuditLog{},
		}
	}

	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}

	searchTerm := params.Q
	searchTermLower := ""
	if params.Q != "" && !params.Exact {
		searchTermLower = strings.ToLower(searchTerm) // 仅在此处转换一次
	}

	matchCount := 0
	offset := (params.Page - 1) * params.Limit
	filteredLogs := make([]AuditLog, 0, params.Limit)

	curr := (c.head - 1 + totalLogs) % totalLogs

	for i := 0; i < totalLogs; i++ {
		log := c.logs[curr]
		isMatched := true

		if params.Q != "" {
			foundInQ := false
			if params.Exact {
				if log.QueryName == searchTerm {
					foundInQ = true
				} else if log.ClientIP == searchTerm {
					foundInQ = true
				} else if log.TraceID == searchTerm {
					foundInQ = true
				} else if log.DomainSet != "" && log.DomainSet == searchTerm {
					foundInQ = true
				} else {
					for _, answer := range log.Answers {
						if answer.Data == searchTerm {
							foundInQ = true
							break
						}
					}
				}
			} else {
				if containsFold(log.QueryName, searchTermLower) {
					foundInQ = true
				} else if containsFold(log.ClientIP, searchTermLower) {
					foundInQ = true
				} else if containsFold(log.TraceID, searchTermLower) {
					foundInQ = true
				} else if log.DomainSet != "" && containsFold(log.DomainSet, searchTermLower) {
					foundInQ = true
				} else {
					for _, answer := range log.Answers {
						if containsFold(answer.Data, searchTermLower) {
							foundInQ = true
							break
						}
					}
				}
			}
			if !foundInQ {
				isMatched = false
			}
		}

		if isMatched && params.ClientIP != "" && log.ClientIP != params.ClientIP {
			isMatched = false
		}
		if isMatched && params.Domain != "" && !strings.Contains(log.QueryName, params.Domain) {
			isMatched = false
		}
		if isMatched && params.AnswerIP != "" {
			found := false
			for _, answer := range log.Answers {
				if (answer.Type == "A" || answer.Type == "AAAA") && answer.Data == params.AnswerIP {
					found = true
					break
				}
			}
			if !found {
				isMatched = false
			}
		}
		if isMatched && params.AnswerCNAME != "" {
			found := false
			for _, answer := range log.Answers {
				if answer.Type == "CNAME" && strings.Contains(answer.Data, params.AnswerCNAME) {
					found = true
					break
				}
			}
			if !found {
				isMatched = false
			}
		}

		if isMatched {
			if matchCount >= offset && len(filteredLogs) < params.Limit {
				filteredLogs = append(filteredLogs, log)
			}
			matchCount++
		}

		curr = (curr - 1 + totalLogs) % totalLogs
	}

	totalPages := int(math.Ceil(float64(matchCount) / float64(params.Limit)))
	return V2PaginatedLogsResponse{
		Pagination: V2PaginationInfo{
			TotalItems:   matchCount,
			TotalPages:   totalPages,
			CurrentPage:  params.Page,
			ItemsPerPage: params.Limit,
		},
		Logs: filteredLogs,
	}
}
