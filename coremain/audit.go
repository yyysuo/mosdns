package coremain

import (
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
	ClientIP   string    `json:"client_ip"`
	QueryType  string    `json:"query_type"`
	QueryName  string    `json:"query_name"`
	QueryClass string    `json:"query_class"` // ADDED
	QueryTime  time.Time `json:"query_time"`
	DurationMs float64   `json:"duration_ms"`
	TraceID    string    `json:"trace_id"`

	// --- Response Details ---
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
	defaultAuditLogCapacity = 10000
	auditChannelCapacity    = 1024
)

type AuditCollector struct {
	mu        sync.Mutex
	capturing bool
	capacity  int
	logs      []AuditLog
	head      int

	ctxChan    chan *query_context.Context
	workerDone chan struct{}
}

var GlobalAuditCollector = NewAuditCollector(defaultAuditLogCapacity)

func NewAuditCollector(capacity int) *AuditCollector {
	return &AuditCollector{
		capturing:  true, // 默认打开日志开关
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
		if c.capacity == 0 { return }
		c.logs[c.head] = log
		c.head = (c.head + 1) % c.capacity
	}
}


// ... (The rest of the file: Collect, Start, Stop, IsCapturing, GetLogs, ClearLogs, GetCapacity, SetCapacity remains unchanged) ...

func (c *AuditCollector) Collect(qCtx *query_context.Context) {
	if c.IsCapturing() {
		select {
		case c.ctxChan <- qCtx:
		default:
		}
	}
}

func (c *AuditCollector) Start() { c.mu.Lock(); c.capturing = true; c.mu.Unlock() }
func (c *AuditCollector) Stop()  { c.mu.Lock(); c.capturing = false; c.mu.Unlock() }
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
	if newCapacity > 100000 {
		newCapacity = 100000
	}

	c.capacity = newCapacity
	c.logs = make([]AuditLog, 0, newCapacity)
	c.head = 0
}
