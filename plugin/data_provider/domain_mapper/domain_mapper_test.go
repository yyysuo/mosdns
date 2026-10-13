package domain_mapper

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func Test_warnSwitchMark(t *testing.T) {
	for mark, wantWarn := range map[uint8]string{0: "", 31: "", 48: "", 32: "switch1", 46: "switch15"} {
		core, logs := observer.New(zapcore.WarnLevel)
		warnSwitchMark(zap.New(core), "default_mark", mark)
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
