package domain_output

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func Test_warnTargetMark(t *testing.T) {
	for mark, wantWarn := range map[uint8]string{0: "", 31: "", 63: "", 40: "switch9", 64: "out of range", 255: "out of range"} {
		core, logs := observer.New(zapcore.WarnLevel)
		warnTargetMark(zap.New(core), mark)
		entries := logs.All()
		if wantWarn == "" {
			if len(entries) != 0 {
				t.Errorf("mark %d: unexpected warning: %s", mark, entries[0].Message)
			}
			continue
		}
		if len(entries) != 1 || !strings.Contains(entries[0].Message, wantWarn) {
			t.Errorf("mark %d: want one warning about %s, got %v", mark, wantWarn, entries)
		}
	}
}
