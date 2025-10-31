package coremain

import (
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogMarkKey 用于在上下文中打标记（布尔开关/跟踪等用途）
const LogMarkKey = 0xFEEDBEEF

// InMemoryLogCollector is a thread-safe in-memory log collector.
type InMemoryLogCollector struct {
	mu        sync.Mutex
	capturing bool
	logs      []map[string]interface{}
	stopTimer *time.Timer
	origLevel zapcore.Level
	hasOrig   bool
}

// GlobalLogCollector is a singleton instance for log capturing.
var GlobalLogCollector = &InMemoryLogCollector{
	logs: make([]map[string]interface{}, 0, 2048), // Pre-allocate capacity
}

// StartCapture begins capturing logs for a given duration.
func (c *InMemoryLogCollector) StartCapture(duration time.Duration, logLevel zap.AtomicLevel) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.capturing {
		if c.stopTimer != nil {
			c.stopTimer.Stop() // Stop previous timer if a new capture starts
		}
	} else {
		c.origLevel = logLevel.Level()
		c.hasOrig = true
	}

	// Reset log buffer for the new capture session.
	c.logs = make([]map[string]interface{}, 0, 2048)
	c.capturing = true
	logLevel.SetLevel(zap.DebugLevel) // Switch to DEBUG level

	c.stopTimer = time.AfterFunc(duration, func() {
		c.StopCapture(logLevel)
	})
}

// StopCapture stops the log capture and resets the log level.
func (c *InMemoryLogCollector) StopCapture(logLevel zap.AtomicLevel) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.capturing {
		return
	}

	if c.hasOrig {
		logLevel.SetLevel(c.origLevel) // Restore to original level
		c.hasOrig = false
	} else {
		logLevel.SetLevel(zap.InfoLevel) // Fallback to INFO
	}
	c.capturing = false
	if c.stopTimer != nil {
		c.stopTimer.Stop()
		c.stopTimer = nil
	}
}

// AddLog adds a structured log entry to the in-memory buffer if capturing is active.
func (c *InMemoryLogCollector) AddLog(entry zapcore.Entry, fields []zapcore.Field) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.capturing {
		return
	}
  
	// Only capture debug level logs into memory.
	if entry.Level != zap.DebugLevel {
		return
	}

	// Convert fields to a map
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range fields {
		f.AddTo(enc)
	}

	// Add standard entry fields
	logMap := enc.Fields
	logMap["level"] = entry.Level.String()
	logMap["time"] = entry.Time
	logMap["msg"] = entry.Message
	logMap["logger_name"] = entry.LoggerName

    // 限制最大容量：达到 cap 时丢弃最旧，保持 O(n) 但 n 较小（默认 2048）。
    if len(c.logs) < cap(c.logs) {
        c.logs = append(c.logs, logMap)
    } else if cap(c.logs) > 0 {
        // 左移一位，覆盖最旧元素。
        copy(c.logs[0:], c.logs[1:])
        c.logs[len(c.logs)-1] = logMap
    } else {
        c.logs = append(c.logs, logMap)
    }
}

// GetLogs returns all captured logs and clears the in-memory buffer.
// This is a "read-once" operation.
func (c *InMemoryLogCollector) GetLogs() []map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Efficiently swap out the logs buffer with a new empty one.
	// This avoids holding the lock while copying and is very fast.
	logsToReturn := c.logs
	c.logs = make([]map[string]interface{}, 0, 2048)

	return logsToReturn
}

// TeeCore is a custom zapcore.Core that writes to two destinations:
// 1. The original core (e.g., a file or console)
// 2. The in-memory log collector
type TeeCore struct {
	zapcore.Core
	collector *InMemoryLogCollector
}

// NewTeeCore creates a new TeeCore.
func NewTeeCore(core zapcore.Core, collector *InMemoryLogCollector) *TeeCore {
	return &TeeCore{
		Core:      core,
		collector: collector,
	}
}

// Write duplicates the log entry to both the original core and the collector.
func (t *TeeCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	// Add log to our in-memory collector
	t.collector.AddLog(entry, fields)

	// Pass the log to the original core (e.g., to write to file/console)
	return t.Core.Write(entry, fields)
}

// Check decides if a log entry should be processed.
func (t *TeeCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if t.Enabled(ent.Level) {
		return ce.AddCore(ent, t)
	}
	return ce
}
