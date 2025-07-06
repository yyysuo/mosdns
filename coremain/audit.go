package coremain

import (
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

	// The buffer size for the async log processing channel.
	auditChannelCapacity = 1024
)

type AuditCollector struct {
	mu         sync.Mutex
	capturing  bool
	capacity   int
	logs       []AuditLog
	head       int
	ctxChan    chan *query_context.Context
	workerDone chan struct{}
}

// --- MODIFIED: Use the new defaultAuditCapacity constant for initialization ---
var GlobalAuditCollector = NewAuditCollector(defaultAuditCapacity)

func NewAuditCollector(capacity int) *AuditCollector {
	return &AuditCollector{
		capturing:  true,
		capacity:   capacity,
		logs:       make([]AuditLog, 0, capacity),
		ctxChan:    make(chan *query_context.Context, auditChannelCapacity),
		workerDone: make(chan struct{}),
	}
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
	log := AuditLog{
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

	if len(c.logs) < c.capacity {
		c.logs = append(c.logs, log)
	} else {
		if c.capacity == 0 {
			return
		}
		c.logs[c.head] = log
		c.head = (c.head + 1) % c.capacity
	}
}

// ... (The rest of the file: Collect, Start, Stop, IsCapturing, GetLogs, ClearLogs, GetCapacity remains unchanged) ...

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
	c.logs = make([]AuditLog, 0, c.capacity)
	c.head = 0
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
	// --- MODIFIED: Use the maxAuditCapacity constant for the upper limit ---
	if newCapacity > maxAuditCapacity {
		newCapacity = maxAuditCapacity
	}

	c.capacity = newCapacity
	c.logs = make([]AuditLog, 0, newCapacity)
	c.head = 0
}

// --- ADDED START: V2 API Support ---
// --- Do not modify any code below this line ---

// V2GetLogsParams holds all filtering and pagination options for the v2 logs API.
type V2GetLogsParams struct {
	Page        int
	Limit       int
	Domain      string
	AnswerIP    string
	AnswerCNAME string
	ClientIP    string
}

// getLogsSnapshot safely creates a copy of the current logs for processing.
// This is crucial to avoid holding the lock for long during calculations.
// It returns a chronologically sorted slice (newest first).
func (c *AuditCollector) getLogsSnapshot() []AuditLog {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.capacity == 0 || len(c.logs) == 0 {
		return []AuditLog{}
	}

	snapshot := make([]AuditLog, len(c.logs))
	if len(c.logs) < c.capacity {
		// If buffer is not full, just copy and reverse.
		copy(snapshot, c.logs)
	} else {
		// If buffer is full (circular), copy in order.
		copy(snapshot, c.logs[c.head:])
		copy(snapshot[c.capacity-c.head:], c.logs[:c.head])
	}

	// Reverse the snapshot to have newest logs first.
	for i, j := 0, len(snapshot)-1; i < j; i, j = i+1, j-1 {
		snapshot[i], snapshot[j] = snapshot[j], snapshot[i]
	}
	return snapshot
}

// 1. CalculateV2Stats computes total queries and average duration.
func (c *AuditCollector) CalculateV2Stats() V2StatsResponse {
	snapshot := c.getLogsSnapshot()
	totalLogs := len(snapshot)
	if totalLogs == 0 {
		return V2StatsResponse{}
	}

	var totalDuration float64
	for i := range snapshot {
		totalDuration += snapshot[i].DurationMs
	}

	return V2StatsResponse{
		TotalQueries:      totalLogs,
		AverageDurationMs: totalDuration / float64(totalLogs),
	}
}

// 2 & 3. CalculateRank is a generic function for domain and client ranking.
func (c *AuditCollector) CalculateRank(keyExtractor func(log *AuditLog) string, limit int) []V2RankItem {
	snapshot := c.getLogsSnapshot()
	if len(snapshot) == 0 {
		return []V2RankItem{}
	}

	counts := make(map[string]int)
	for i := range snapshot {
		key := keyExtractor(&snapshot[i])
		if key != "" {
			counts[key]++
		}
	}

	rankList := make([]V2RankItem, 0, len(counts))
	for key, count := range counts {
		rankList = append(rankList, V2RankItem{Key: key, Count: count})
	}

	sort.Slice(rankList, func(i, j int) bool {
		return rankList[i].Count > rankList[j].Count // Sort descending
	})

	if len(rankList) > limit {
		return rankList[:limit]
	}
	return rankList
}

// 4. GetSlowestQueries returns logs sorted by duration.
func (c *AuditCollector) GetSlowestQueries(limit int) []AuditLog {
	snapshot := c.getLogsSnapshot()

	sort.SliceStable(snapshot, func(i, j int) bool {
		return snapshot[i].DurationMs > snapshot[j].DurationMs // Sort descending
	})

	if len(snapshot) > limit {
		return snapshot[:limit]
	}
	return snapshot
}

// 5. GetV2Logs provides advanced filtering and pagination.
func (c *AuditCollector) GetV2Logs(params V2GetLogsParams) V2PaginatedLogsResponse {
	snapshot := c.getLogsSnapshot()

	// Apply filters
	filteredLogs := make([]AuditLog, 0, len(snapshot))
	for _, log := range snapshot {
		// Client IP filter (exact match)
		if params.ClientIP != "" && log.ClientIP != params.ClientIP {
			continue
		}
		// Domain filter (contains)
		if params.Domain != "" && !strings.Contains(log.QueryName, params.Domain) {
			continue
		}
		// Answer IP filter
		if params.AnswerIP != "" {
			found := false
			for _, answer := range log.Answers {
				if answer.Type == "A" || answer.Type == "AAAA" {
					if answer.Data == params.AnswerIP {
						found = true
						break
					}
				}
			}
			if !found {
				continue
			}
		}
		// CNAME filter
		if params.AnswerCNAME != "" {
			found := false
			for _, answer := range log.Answers {
				if answer.Type == "CNAME" {
					// Use strings.Contains for partial match on CNAME target
					if strings.Contains(answer.Data, params.AnswerCNAME) {
						found = true
						break
					}
				}
			}
			if !found {
				continue
			}
		}

		filteredLogs = append(filteredLogs, log)
	}

	// Apply pagination
	totalItems := len(filteredLogs)
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Limit < 1 {
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
		Pagination: V2PaginationInfo{
			TotalItems:   totalItems,
			TotalPages:   totalPages,
			CurrentPage:  params.Page,
			ItemsPerPage: params.Limit,
		},
		Logs: paginatedLogs,
	}
}

// --- ADDED END: V2 API Support ---
