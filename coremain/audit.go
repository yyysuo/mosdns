package coremain

import (
	"container/heap"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

// ADDED: A new struct to hold detailed answer info, including TTL.
type AnswerDetail struct {
	Type string `json:"type"` // e.g., "A", "AAAA", "CNAME"
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"` // e.g., "1.2.3.4", "example.com."
}

// MODIFIED: AuditLog struct is enhanced with more details.
type AuditLog struct {
	ClientIP      string         `json:"client_ip"`
	QueryType     string         `json:"query_type"`
	QueryName     string         `json:"query_name"`
	QueryClass    string         `json:"query_class"` // ADDED
	QueryTime     time.Time      `json:"query_time"`
	DurationMs    float64        `json:"duration_ms"`
	TraceID       string         `json:"trace_id"`
	ResponseCode  string         `json:"response_code"`  // ADDED: e.g., "NOERROR", "NXDOMAIN"
	ResponseFlags ResponseFlags  `json:"response_flags"` // ADDED: Struct for flags
	Answers       []AnswerDetail `json:"answers"`        // MODIFIED: Now a slice of structs
}

// ADDED: A struct to group response flags for clarity in JSON.
type ResponseFlags struct {
	AA bool `json:"aa"` // Authoritative Answer
	TC bool `json:"tc"` // Truncated
	RA bool `json:"ra"` // Recursion Available
}

const (
	// --- MODIFIED: Use named constants for better clarity and maintenance ---
	// Default and recommended capacity. A good balance between features and performance.
	defaultAuditCapacity = 100000

	// The absolute maximum capacity allowed. Exceeding this may cause performance issues.
	maxAuditCapacity = 400000

	// --- ADDED: The capacity for our slowest queries heap ---
	slowestQueriesCapacity = 300

	// The buffer size for the async log processing channel.
	auditChannelCapacity = 1024
)

// --- ADDED: A new type for our min-heap of slowest queries ---
type slowestQueryHeap []*AuditLog

func (h slowestQueryHeap) Len() int           { return len(h) }
func (h slowestQueryHeap) Less(i, j int) bool { return h[i].DurationMs < h[j].DurationMs } // Min-heap based on duration
func (h slowestQueryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *slowestQueryHeap) Push(x any) {
	*h = append(*h, x.(*AuditLog))
}

func (h *slowestQueryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

type AuditCollector struct {
	mu        sync.Mutex
	capturing bool

	// Main log storage
	capacity int
	logs     []AuditLog
	head     int

	// --- ADDED: Dedicated storage for slowest queries using a min-heap ---
	slowestQueries slowestQueryHeap

	// --- ADDED: Real-time counters for ranking ---
	domainCounts map[string]int
	clientCounts map[string]int

	// --- ADDED: Real-time aggregated stats ---
	totalQueryCount    uint64
	totalQueryDuration float64

	ctxChan    chan *query_context.Context
	workerDone chan struct{}
}

// --- MODIFIED: Use the new defaultAuditCapacity constant for initialization ---
var GlobalAuditCollector = NewAuditCollector(defaultAuditCapacity)

func NewAuditCollector(capacity int) *AuditCollector {
	// --- MODIFIED: Initialize all dedicated storage structures ---
	c := &AuditCollector{
		capturing:          true,
		capacity:           capacity,
		logs:               make([]AuditLog, 0, capacity),
		slowestQueries:     make(slowestQueryHeap, 0, slowestQueriesCapacity),
		domainCounts:       make(map[string]int),
		clientCounts:       make(map[string]int),
		totalQueryCount:    0,
		totalQueryDuration: 0.0,
		ctxChan:            make(chan *query_context.Context, auditChannelCapacity),
		workerDone:         make(chan struct{}),
	}
	heap.Init(&c.slowestQueries)
	return c
}

// ... (StartWorker, StopWorker, worker functions remain unchanged) ...
func (c *AuditCollector) StartWorker() {
	go c.worker()
}

func (c *AuditCollector) StopWorker() {
	close(c.ctxChan)
	<-c.workerDone
}

func (c *AuditCollector) worker() {
	defer close(c.workerDone)
	for qCtx := range c.ctxChan {
		if qCtx != nil {
			c.processContext(qCtx)
		}
	}
}

// MODIFIED: Completely rewritten to extract and populate the new fields.
func (c *AuditCollector) processContext(qCtx *query_context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.capturing {
		return
	}

	qQuestion := qCtx.QQuestion()
	// --- MODIFIED: Create a pointer to the log to avoid duplicating the object in memory ---
	log := &AuditLog{
		ClientIP:   qCtx.ServerMeta.ClientAddr.String(),
		QueryType:  dns.TypeToString[qQuestion.Qtype],
		QueryName:  strings.TrimSuffix(qQuestion.Name, "."),
		QueryClass: dns.ClassToString[qQuestion.Qclass], // Populate QueryClass
		QueryTime:  qCtx.StartTime(),
		DurationMs: float64(time.Since(qCtx.StartTime()).Microseconds()) / 1000.0,
		TraceID:    qCtx.TraceID,
		// Initialize slices/maps
		Answers: []AnswerDetail{},
	}

	if resp := qCtx.R(); resp != nil {
		// Populate Response Code and Flags
		log.ResponseCode = dns.RcodeToString[resp.Rcode]
		log.ResponseFlags = ResponseFlags{
			AA: resp.Authoritative,
			TC: resp.Truncated,
			RA: resp.RecursionAvailable,
		}

		// Populate detailed answers
		for _, ans := range resp.Answer {
			header := ans.Header()
			detail := AnswerDetail{
				Type: dns.TypeToString[header.Rrtype],
				TTL:  header.Ttl,
			}

			switch record := ans.(type) {
			case *dns.A:
				detail.Data = record.A.String()
			case *dns.AAAA:
				detail.Data = record.AAAA.String()
			case *dns.CNAME:
				detail.Data = record.Target
			case *dns.PTR:
				detail.Data = record.Ptr
			case *dns.NS:
				detail.Data = record.Ns
			case *dns.MX:
				detail.Data = record.Mx
			case *dns.TXT:
				detail.Data = strings.Join(record.Txt, " ") // Join TXT strings
			default:
				// For other types, use the generic string representation.
				detail.Data = ans.String()
			}
			log.Answers = append(log.Answers, detail)
		}
	} else {
		// If there is no response message, set a default error code.
		log.ResponseCode = "NO_RESPONSE"
	}

	// --- MODIFIED: Store a value copy in the main ring buffer and handle counter decrement ---
	if len(c.logs) < c.capacity {
		c.logs = append(c.logs, *log)
	} else {
		if c.capacity == 0 {
			return
		}
		// Decrement count for the log being overwritten
		oldLog := c.logs[c.head]
		c.domainCounts[oldLog.QueryName]--
		if c.domainCounts[oldLog.QueryName] <= 0 {
			delete(c.domainCounts, oldLog.QueryName)
		}
		c.clientCounts[oldLog.ClientIP]--
		if c.clientCounts[oldLog.ClientIP] <= 0 {
			delete(c.clientCounts, oldLog.ClientIP)
		}
		// --- ADDED: Decrement total duration for the overwritten log ---
		c.totalQueryDuration -= oldLog.DurationMs

		c.logs[c.head] = *log
		c.head = (c.head + 1) % c.capacity
	}

	// --- MODIFIED: Update all real-time caches ---
	
	// 1. Update slowest queries heap
	if c.slowestQueries.Len() < slowestQueriesCapacity {
		heap.Push(&c.slowestQueries, log)
	} else if log.DurationMs > c.slowestQueries[0].DurationMs { // heap[0] is the minimum element (the "fastest" of the "slowest")
		heap.Pop(&c.slowestQueries)
		heap.Push(&c.slowestQueries, log)
	}

	// 2. Update real-time counters for ranking
	c.domainCounts[log.QueryName]++
	c.clientCounts[log.ClientIP]++

	// 3. Update real-time aggregated stats
	c.totalQueryCount++
	c.totalQueryDuration += log.DurationMs
}

// ... (The rest of the file: Collect, Start, Stop, IsCapturing, GetLogs remains unchanged) ...

func (c *AuditCollector) Collect(qCtx *query_context.Context) {
	if c.IsCapturing() {
		select {
		case c.ctxChan <- qCtx:
		default:
		}
	}
}

func (c *AuditCollector) Start()          { c.mu.Lock(); c.capturing = true; c.mu.Unlock() }
func (c *AuditCollector) Stop()           { c.mu.Lock(); c.capturing = false; c.mu.Unlock() }
func (c *AuditCollector) IsCapturing() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.capturing }

func (c *AuditCollector) GetLogs() []AuditLog {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	
	// Clear main log buffer
	c.logs = make([]AuditLog, 0, c.capacity)
	c.head = 0

	// --- MODIFIED: Also clear all dedicated caches to keep data consistent ---
	c.slowestQueries = make(slowestQueryHeap, 0, slowestQueriesCapacity)
	heap.Init(&c.slowestQueries)
	c.domainCounts = make(map[string]int)
	c.clientCounts = make(map[string]int)
	c.totalQueryCount = 0
	c.totalQueryDuration = 0.0
}

func (c *AuditCollector) GetCapacity() int {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	// --- MODIFIED: Clear all storages when capacity changes ---
	c.logs = make([]AuditLog, 0, newCapacity)
	c.head = 0
	c.slowestQueries = make(slowestQueryHeap, 0, slowestQueriesCapacity)
	heap.Init(&c.slowestQueries)
	c.domainCounts = make(map[string]int)
	c.clientCounts = make(map[string]int)
	c.totalQueryCount = 0
	c.totalQueryDuration = 0.0
}

// V2GetLogsParams holds all filtering and pagination options for the v2 logs API.
type V2GetLogsParams struct {
	Page        int
	Limit       int
	Domain      string
	AnswerIP    string
	AnswerCNAME string
	ClientIP    string
	Q           string // Global search query
	Exact       bool   // Flag to indicate exact matching
}

// getLogsSnapshot safely creates a copy of the current logs for processing.
func (c *AuditCollector) getLogsSnapshot() []AuditLog {
	c.mu.Lock()
	defer c.mu.Unlock()

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

// --- REWRITTEN: CalculateV2Stats now efficiently uses real-time aggregated values ---
func (c *AuditCollector) CalculateV2Stats() V2StatsResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	avgDuration := 0.0
	logCount := len(c.logs)

	if logCount > 0 {
		avgDuration = c.totalQueryDuration / float64(logCount)
	}

	return V2StatsResponse{
		TotalQueries:      int(c.totalQueryCount),
		AverageDurationMs: avgDuration,
	}
}

// --- ADDED: A robust internal helper for creating ranks from maps ---
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

// --- REWRITTEN: CalculateRank now efficiently uses the real-time counter maps ---
func (c *AuditCollector) CalculateRank(keyExtractor func(log *AuditLog) string, limit int) []V2RankItem {
	c.mu.Lock()
	defer c.mu.Unlock()

	// This is a robust way to determine which map to use, without making assumptions
	// about the keyExtractor's internal workings.
	tempLog := &AuditLog{QueryName: "domain", ClientIP: "client"}
	if keyExtractor(tempLog) == "domain" {
		return c.getRankFromMap(c.domainCounts, limit)
	} else {
		return c.getRankFromMap(c.clientCounts, limit)
	}
}

// --- REWRITTEN: GetSlowestQueries now efficiently retrieves data from the heap ---
func (c *AuditCollector) GetSlowestQueries(limit int) []AuditLog {
	c.mu.Lock()
	defer c.mu.Unlock()

	// The heap contains pointers, so we create a new slice of values for the response.
	// This also prevents any race conditions if the heap is modified concurrently.
	snapshot := make([]AuditLog, c.slowestQueries.Len())
	for i, logPtr := range c.slowestQueries {
		snapshot[i] = *logPtr // Dereference the pointer to create a value copy
	}

	// Sort the small snapshot in descending order of duration for display.
	sort.Slice(snapshot, func(i, j int) bool {
		return snapshot[i].DurationMs > snapshot[j].DurationMs
	})

	if len(snapshot) > limit {
		return snapshot[:limit]
	}
	return snapshot
}

// GetV2Logs provides advanced filtering and pagination with both exact and contains search support.
func (c *AuditCollector) GetV2Logs(params V2GetLogsParams) V2PaginatedLogsResponse {
	snapshot := c.getLogsSnapshot()
	filteredLogs := make([]AuditLog, 0, len(snapshot))

	for _, log := range snapshot {
		// Global search filter (`q`) with exact/contains logic
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
			if !params.Exact { haystack = strings.ToLower(haystack) }
			if matchFunc(haystack, searchTerm) {
				foundInQ = true
			}
			
			// Check ClientIP
			if !foundInQ {
				haystack = log.ClientIP
				if !params.Exact { haystack = strings.ToLower(haystack) } // Note: IP usually doesn't need ToLower, but for contains it's safer
				if matchFunc(haystack, searchTerm) {
					foundInQ = true
				}
			}

			// Check Answers
			if !foundInQ {
				for _, answer := range log.Answers {
					haystack = answer.Data
					if !params.Exact { haystack = strings.ToLower(haystack) }
					if matchFunc(haystack, searchTerm) {
						foundInQ = true
						break
					}
				}
			}

			if !foundInQ {
				continue // If q is provided and no match, skip this log
			}
		}

		// Specific filters (can be used in combination with `q`)
		if params.ClientIP != "" && log.ClientIP != params.ClientIP { continue }
		if params.Domain != "" && !strings.Contains(log.QueryName, params.Domain) { continue }
		if params.AnswerIP != "" {
			found := false
			for _, answer := range log.Answers {
				if (answer.Type == "A" || answer.Type == "AAAA") && answer.Data == params.AnswerIP {
					found = true; break
				}
			}
			if !found { continue }
		}
		if params.AnswerCNAME != "" {
			found := false
			for _, answer := range log.Answers {
				if answer.Type == "CNAME" && strings.Contains(answer.Data, params.AnswerCNAME) {
					found = true; break
				}
			}
			if !found { continue }
		}

		filteredLogs = append(filteredLogs, log)
	}

	// Apply pagination
	totalItems := len(filteredLogs)
	if params.Page < 1 { params.Page = 1 }
	if params.Limit <= 0 { params.Limit = 50 }
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
