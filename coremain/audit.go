// /root/mosdns/coremain/audit.go
package coremain

import (
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

type AuditLog struct {
	ClientIP   string    `json:"client_ip"`
	QueryType  string    `json:"query_type"`
	QueryName  string    `json:"query_name"`
	Answers    []string  `json:"answers"`
	QueryTime  time.Time `json:"query_time"`
	DurationMs float64   `json:"duration_ms"`
	TraceID    string    `json:"trace_id"`
}

// MODIFIED: Default capacity is now 10000.
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
		capacity:   capacity,
		logs:       make([]AuditLog, 0, capacity),
		ctxChan:    make(chan *query_context.Context, auditChannelCapacity),
		workerDone: make(chan struct{}),
	}
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
	for qCtx := range c.ctxChan {
		if qCtx != nil {
			c.processContext(qCtx)
		}
	}
}

func (c *AuditCollector) processContext(qCtx *query_context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.capturing {
		return
	}

	answers := []string{}
	if resp := qCtx.R(); resp != nil {
		for _, ans := range resp.Answer {
			switch ans.Header().Rrtype {
			case dns.TypeA:
				if a, ok := ans.(*dns.A); ok {
					answers = append(answers, a.A.String())
				}
			case dns.TypeAAAA:
				if aaaa, ok := ans.(*dns.AAAA); ok {
					answers = append(answers, aaaa.AAAA.String())
				}
			case dns.TypeCNAME:
				if cname, ok := ans.(*dns.CNAME); ok {
					answers = append(answers, cname.Target)
				}
			}
		}
	}

	log := AuditLog{
		ClientIP:   qCtx.ServerMeta.ClientAddr.String(),
		QueryType:  dns.TypeToString[qCtx.QQuestion().Qtype],
		QueryName:  strings.TrimSuffix(qCtx.QQuestion().Name, "."),
		Answers:    answers,
		QueryTime:  qCtx.StartTime(),
		DurationMs: float64(time.Since(qCtx.StartTime()).Microseconds()) / 1000.0,
		TraceID:    qCtx.TraceID,
	}

	if len(c.logs) < c.capacity {
		c.logs = append(c.logs, log)
	} else {
		if c.capacity == 0 { return } // Avoid division by zero if capacity is set to 0
		c.logs[c.head] = log
		c.head = (c.head + 1) % c.capacity
	}
}

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

// ADDED: GetCapacity returns the current capacity of the log buffer.
func (c *AuditCollector) GetCapacity() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.capacity
}

// ADDED: SetCapacity changes the size of the log buffer.
// This will also clear all existing logs.
func (c *AuditCollector) SetCapacity(newCapacity int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Add reasonable limits for capacity
	if newCapacity < 0 {
		newCapacity = 0
	}
	if newCapacity > 100000 { // Prevent setting excessively large capacity
		newCapacity = 100000
	}

	c.capacity = newCapacity
	c.logs = make([]AuditLog, 0, newCapacity)
	c.head = 0
}
