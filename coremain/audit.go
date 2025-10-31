package coremain

import (
	"container/heap"
	"container/list"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

// 字符串驻留：使用定长、并发安全的 LRU 缓存降低重复字符串分配
const lruCacheSize = 16384 // Define a reasonable size for the string cache

type lruEntry struct {
	key   string
	value string
}

type lruCache struct {
	mu       sync.Mutex
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
	l.mu.Lock()
	defer l.mu.Unlock()

	if elem, hit := l.cache[key]; hit {
		l.ll.MoveToFront(elem)
		return elem.Value.(*lruEntry).value, true
	}
	return "", false
}

func (l *lruCache) Put(key, value string) {
	l.mu.Lock()
	defer l.mu.Unlock()

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

var globalStringLRU = newLRUCache(lruCacheSize)

func internString(s string) string {
	if val, ok := globalStringLRU.Get(s); ok {
		return val
	}
	globalStringLRU.Put(s, s)
	return s
}

// 包装上下文：携带处理耗时用于审计统计
type auditContext struct {
	Ctx                *query_context.Context
	ProcessingDuration time.Duration
}

// 详细答案信息（含 TTL）
type AnswerDetail struct {
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// 审计日志结构，包含查询/响应要点
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

// 响应标志位封装，便于 JSON 输出
type ResponseFlags struct {
	AA bool `json:"aa"`
	TC bool `json:"tc"`
	RA bool `json:"ra"`
}

const (
	defaultAuditCapacity   = 100000
	maxAuditCapacity       = 400000
	slowestQueriesCapacity = 300
	auditChannelCapacity   = 1024
)

// 最慢查询小顶堆，按耗时排序，存值类型（非指针）
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
	capturing          bool
	capacity           int
	logs               []AuditLog
	head               int
	slowestQueries     slowestQueryHeap
	domainCounts       map[string]int
	clientCounts       map[string]int
	domainSetCounts    map[string]int
	totalQueryCount    uint64
	totalQueryDuration float64
	ctxChan            chan *auditContext
	workerDone         chan struct{}
}

var GlobalAuditCollector = NewAuditCollector(defaultAuditCapacity)

func NewAuditCollector(capacity int) *AuditCollector {
	c := &AuditCollector{
		capturing:          true,
		capacity:           capacity,
		logs:               make([]AuditLog, 0, capacity),
		slowestQueries:     make(slowestQueryHeap, 0, slowestQueriesCapacity),
		domainCounts:       make(map[string]int),
		clientCounts:       make(map[string]int),
		domainSetCounts:    make(map[string]int),
		totalQueryCount:    0,
		totalQueryDuration: 0.0,
		ctxChan:            make(chan *auditContext, auditChannelCapacity),
		workerDone:         make(chan struct{}),
	}
	heap.Init(&c.slowestQueries)
	return c
}

func (c *AuditCollector) StartWorker() {
	go c.worker()
}

func (c *AuditCollector) StopWorker() {
	close(c.ctxChan)
	<-c.workerDone
}

func (c *AuditCollector) worker() {
	defer close(c.workerDone)
	for wrappedCtx := range c.ctxChan {
		if wrappedCtx != nil && wrappedCtx.Ctx != nil {
			c.processContext(wrappedCtx)
		}
	}
}

// 处理单条审计日志（入堆与聚合）
func (c *AuditCollector) processContext(wrappedCtx *auditContext) {
	// STEP 1: All preparation work is done OUTSIDE the main lock.
	qCtx := wrappedCtx.Ctx
	qQuestion := qCtx.QQuestion()
	duration := wrappedCtx.ProcessingDuration

	log := AuditLog{
		ClientIP:   internString(qCtx.ServerMeta.ClientAddr.String()),
		QueryType:  internString(dns.TypeToString[qQuestion.Qtype]),
		QueryName:  internString(strings.TrimSuffix(qQuestion.Name, ".")),
		QueryClass: internString(dns.ClassToString[qQuestion.Qclass]),
		QueryTime:  qCtx.StartTime(),
		DurationMs: float64(duration.Microseconds()) / 1000.0,
		TraceID:    qCtx.TraceID,
	}

	if val, ok := qCtx.GetValue(query_context.KeyDomainSet); ok {
		if name, isString := val.(string); isString {
			log.DomainSet = name
		}
	}

    // 若未命中任何域名集合，标记为 "unmatched_rule"
	if log.DomainSet == "" {
		log.DomainSet = "unmatched_rule"
	}
	// --- ADDED END ---

	if resp := qCtx.R(); resp != nil {
		log.ResponseCode = internString(dns.RcodeToString[resp.Rcode])
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
					Type: internString(dns.TypeToString[header.Rrtype]),
					TTL:  header.Ttl,
				}
				switch record := ans.(type) {
				case *dns.A:
					detail.Data = internString(record.A.String())
				case *dns.AAAA:
					detail.Data = internString(record.AAAA.String())
				case *dns.CNAME:
					detail.Data = internString(record.Target)
				case *dns.PTR:
					detail.Data = internString(record.Ptr)
				case *dns.NS:
					detail.Data = internString(record.Ns)
				case *dns.MX:
					detail.Data = internString(record.Mx)
				case *dns.TXT:
					detail.Data = internString(strings.Join(record.Txt, " "))
				default:
					detail.Data = internString(ans.String())
				}
				log.Answers = append(log.Answers, detail)
			}
		}
	} else {
		log.ResponseCode = internString("NO_RESPONSE")
	}

	// STEP 2: Acquire the lock ONLY to modify shared data structures.
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.capturing {
		return
	}

	if len(c.logs) < c.capacity {
		c.logs = append(c.logs, log)
	} else {
		if c.capacity == 0 {
			return
		}
		oldLog := c.logs[c.head]
		c.domainCounts[oldLog.QueryName]--
		if c.domainCounts[oldLog.QueryName] <= 0 {
			delete(c.domainCounts, oldLog.QueryName)
		}
		c.clientCounts[oldLog.ClientIP]--
		if c.clientCounts[oldLog.ClientIP] <= 0 {
			delete(c.clientCounts, oldLog.ClientIP)
		}

        // 移除被覆盖日志对应的 DomainSet 计数
		c.domainSetCounts[oldLog.DomainSet]--
		if c.domainSetCounts[oldLog.DomainSet] <= 0 {
			delete(c.domainSetCounts, oldLog.DomainSet)
		}
		// --- MODIFIED END ---

		c.totalQueryDuration -= oldLog.DurationMs
		c.totalQueryCount--

		c.logs[c.head] = log
		c.head = (c.head + 1) % c.capacity
	}

	if c.slowestQueries.Len() < slowestQueriesCapacity {
		heap.Push(&c.slowestQueries, log)
	} else if log.DurationMs > c.slowestQueries[0].DurationMs {
		c.slowestQueries[0] = log
		heap.Fix(&c.slowestQueries, 0)
	}

	c.domainCounts[log.QueryName]++
	c.clientCounts[log.ClientIP]++

    // 增加当前日志的 DomainSet 计数
	c.domainSetCounts[log.DomainSet]++
	// --- MODIFIED END ---

	c.totalQueryCount++
	c.totalQueryDuration += log.DurationMs
}

// --- Collect and other functions remain unchanged ---
// ... (The rest of the file is exactly the same as before)
func (c *AuditCollector) Collect(qCtx *query_context.Context) {
	duration := time.Since(qCtx.StartTime())

	wrappedCtx := &auditContext{
		Ctx:                qCtx,
		ProcessingDuration: duration,
	}

	if c.IsCapturing() {
		select {
		case c.ctxChan <- wrappedCtx:
		default:
		}
	}
}

func (c *AuditCollector) Start() { c.mu.Lock(); c.capturing = true; c.mu.Unlock() }
func (c *AuditCollector) Stop()  { c.mu.Lock(); c.capturing = false; c.mu.Unlock() }
func (c *AuditCollector) IsCapturing() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.capturing
}

func (c *AuditCollector) GetLogs() []AuditLog {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.capacity == 0 || len(c.logs) == 0 {
		return []AuditLog{}
	}

	if len(c.logs) < c.capacity {
		logsCopy := make([]AuditLog, len(c.logs))
		copy(logsCopy, c.logs)
		return logsCopy
	}

	logsCopy := make([]AuditLog, c.capacity)
	copy(logsCopy, c.logs[c.head:])
	copy(logsCopy[c.capacity-c.head:], c.logs[:c.head])
	return logsCopy
}

func (c *AuditCollector) ClearLogs() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logs = make([]AuditLog, 0, c.capacity)
	c.head = 0
	c.slowestQueries = make(slowestQueryHeap, 0, slowestQueriesCapacity)
	heap.Init(&c.slowestQueries)
	c.domainCounts = make(map[string]int)
	c.clientCounts = make(map[string]int)
	c.domainSetCounts = make(map[string]int)
	c.totalQueryCount = 0
	c.totalQueryDuration = 0.0
}

func (c *AuditCollector) GetCapacity() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.capacity
}

func (c *AuditCollector) SetCapacity(newCapacity int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if newCapacity < 0 {
		newCapacity = 0
	}
	if newCapacity > maxAuditCapacity {
		newCapacity = maxAuditCapacity
	}

	c.capacity = newCapacity
	c.logs = make([]AuditLog, 0, newCapacity)
	c.head = 0
	c.slowestQueries = make(slowestQueryHeap, 0, slowestQueriesCapacity)
	heap.Init(&c.slowestQueries)
	c.domainCounts = make(map[string]int)
	c.clientCounts = make(map[string]int)
	c.domainSetCounts = make(map[string]int)
	c.totalQueryCount = 0
	c.totalQueryDuration = 0.0
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

func (c *AuditCollector) getLogsSnapshot() []AuditLog {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.capacity == 0 || len(c.logs) == 0 {
		return []AuditLog{}
	}

	snapshot := make([]AuditLog, len(c.logs))
	if len(c.logs) < c.capacity {
		copy(snapshot, c.logs)
	} else {
		copy(snapshot, c.logs[c.head:])
		copy(snapshot[c.capacity-c.head:], c.logs[:c.head])
	}

	for i, j := 0, len(snapshot)-1; i < j; i, j = i+1, j-1 {
		snapshot[i], snapshot[j] = snapshot[j], snapshot[i]
	}
	return snapshot
}

func (c *AuditCollector) CalculateV2Stats() V2StatsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()

	avgDuration := 0.0
	if c.totalQueryCount > 0 {
		avgDuration = c.totalQueryDuration / float64(c.totalQueryCount)
	}

	return V2StatsResponse{
		TotalQueries:      c.totalQueryCount,
		AverageDurationMs: avgDuration,
	}
}

func (c *AuditCollector) getRankFromMap(sourceMap map[string]int, limit int) []V2RankItem {
	if len(sourceMap) == 0 {
		return []V2RankItem{}
	}

	rankList := make([]V2RankItem, 0, len(sourceMap))
	for key, count := range sourceMap {
		rankList = append(rankList, V2RankItem{Key: key, Count: count})
	}

	sort.Slice(rankList, func(i, j int) bool {
		return rankList[i].Count > rankList[j].Count
	})

	if len(rankList) > limit {
		return rankList[:limit]
	}
	return rankList
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

func (c *AuditCollector) GetV2Logs(params V2GetLogsParams) V2PaginatedLogsResponse {
	snapshot := c.getLogsSnapshot()
	filteredLogs := make([]AuditLog, 0, len(snapshot))

	for _, log := range snapshot {
		if params.Q != "" {
			var matchFunc func(string, string) bool
			searchTerm := params.Q
			if params.Exact {
				matchFunc = func(s, substr string) bool { return s == substr }
			} else {
				matchFunc = strings.Contains
				searchTerm = strings.ToLower(searchTerm)
			}
			foundInQ := false
			var haystack string

			// Check QueryName
			haystack = log.QueryName
			if !params.Exact {
				haystack = strings.ToLower(haystack)
			}
			if matchFunc(haystack, searchTerm) {
				foundInQ = true
			}

			// Check ClientIP
			if !foundInQ {
				haystack = log.ClientIP
				if !params.Exact {
					haystack = strings.ToLower(haystack)
				}
				if matchFunc(haystack, searchTerm) {
					foundInQ = true
				}
			}

			// Check TraceID
			if !foundInQ {
				haystack = log.TraceID
				if !params.Exact {
					haystack = strings.ToLower(haystack)
				}
				if matchFunc(haystack, searchTerm) {
					foundInQ = true
				}
			}
			
			// Check DomainSet
			if !foundInQ && log.DomainSet != "" {
				haystack = log.DomainSet
				if !params.Exact {
					haystack = strings.ToLower(haystack)
				}
				if matchFunc(haystack, searchTerm) {
					foundInQ = true
				}
			}

			// Check Answers
			if !foundInQ {
				for _, answer := range log.Answers {
					haystack = answer.Data
					if !params.Exact {
						haystack = strings.ToLower(haystack)
					}
					if matchFunc(haystack, searchTerm) {
						foundInQ = true
						break
					}
				}
			}
			if !foundInQ {
				continue
			}
		}

		if params.ClientIP != "" && log.ClientIP != params.ClientIP {
			continue
		}
		if params.Domain != "" && !strings.Contains(log.QueryName, params.Domain) {
			continue
		}
		if params.AnswerIP != "" {
			found := false
			for _, answer := range log.Answers {
				if (answer.Type == "A" || answer.Type == "AAAA") && answer.Data == params.AnswerIP {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if params.AnswerCNAME != "" {
			found := false
			for _, answer := range log.Answers {
				if answer.Type == "CNAME" && strings.Contains(answer.Data, params.AnswerCNAME) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		filteredLogs = append(filteredLogs, log)
	}

	totalItems := len(filteredLogs)
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}
	totalPages := int(math.Ceil(float64(totalItems) / float64(params.Limit)))
	offset := (params.Page - 1) * params.Limit

	var paginatedLogs []AuditLog
	if offset >= totalItems {
		paginatedLogs = []AuditLog{}
	} else {
		end := offset + params.Limit
		if end > totalItems {
			end = totalItems
		}
		paginatedLogs = filteredLogs[offset:end]
	}

	return V2PaginatedLogsResponse{
		Pagination: V2PaginationInfo{TotalItems: totalItems, TotalPages: totalPages, CurrentPage: params.Page, ItemsPerPage: params.Limit},
		Logs:       paginatedLogs,
	}
}
