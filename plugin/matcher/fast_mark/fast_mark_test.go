package fast_mark

import (
	"context"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func Test_newFastMarker_switchBitWarning(t *testing.T) {
	tests := []struct {
		args     string
		wantWarn string // "" means no warning
	}{
		{args: "29"},
		{args: "31 48"},
		{args: "32", wantWarn: "switch1"},
		{args: "1 39", wantWarn: "switch8"},
		{args: "47", wantWarn: "switch16"},
	}
	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			core, logs := observer.New(zapcore.WarnLevel)
			m, err := newFastMarker(tt.args, zap.New(core))
			if err != nil {
				t.Fatalf("switch bits must be accepted, got err: %v", err)
			}
			if m == nil {
				t.Fatal("nil marker")
			}
			entries := logs.All()
			if tt.wantWarn == "" {
				if len(entries) != 0 {
					t.Fatalf("unexpected warning: %s", entries[0].Message)
				}
				return
			}
			if len(entries) != 1 || !strings.Contains(entries[0].Message, tt.wantWarn) {
				t.Fatalf("want one warning about %s, got %v", tt.wantWarn, entries)
			}
		})
	}
}

func Test_newFastMarker_outOfRange(t *testing.T) {
	if _, err := newFastMarker("64", zap.NewNop()); err == nil {
		t.Fatal("ID 64 should be rejected")
	}
}

// fast_mark 39 keeps its old behavior (it follows switch8), it is only warned.
func Test_fastMark_switchBitFollowsSwitch(t *testing.T) {
	old := query_context.GlobalSwitchMask.Load()
	defer query_context.GlobalSwitchMask.Store(old)

	m, err := newFastMarker("39", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	for _, on := range []bool{true, false} {
		mask := uint64(0)
		if on {
			mask = 1 << 39
		}
		query_context.GlobalSwitchMask.Store(mask)
		got, _ := m.Match(context.Background(), query_context.NewContext(q))
		if got != on {
			t.Fatalf("switch8 on=%v: fast_mark 39 matched=%v", on, got)
		}
	}
}
