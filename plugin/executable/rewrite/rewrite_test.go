package rewrite

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func Test_parseRewriteTarget(t *testing.T) {
	tests := []struct {
		rule    string
		wantIPs []string // nil for a domain target
		wantDom string
		wantErr bool
	}{
		{rule: "a.com 1.2.3.4", wantIPs: []string{"1.2.3.4"}},
		{rule: "a.com 2001:db8::1", wantIPs: []string{"2001:db8::1"}},
		{rule: "a.com b.com", wantDom: "b.com."},
		{rule: "a.com 192.168.1.10 2001:db8::10", wantIPs: []string{"192.168.1.10", "2001:db8::10"}},
		{rule: "a.com 10.0.0.1 10.0.0.2 10.0.0.3", wantIPs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{rule: "a.com 10.0.0.1 b.com", wantErr: true},
		{rule: "a.com b.com 10.0.0.1", wantErr: true},
		{rule: "a.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			_, res, err := parseRewriteTarget(tt.rule)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantIPs == nil {
				if res.isIP || res.domain != tt.wantDom {
					t.Fatalf("want domain target %s, got %+v", tt.wantDom, res)
				}
				return
			}
			var got []string
			for _, ip := range res.ips {
				got = append(got, ip.String())
			}
			if !res.isIP || !reflect.DeepEqual(got, tt.wantIPs) {
				t.Fatalf("want IPs %v, got %+v", tt.wantIPs, got)
			}
		})
	}
}

func Test_parseRewriteTarget_maxIPs(t *testing.T) {
	rule := func(n int) string {
		var b strings.Builder
		b.WriteString("a.com")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, " 10.0.0.%d", i)
		}
		return b.String()
	}
	_, res, err := parseRewriteTarget(rule(maxIPsPerRule))
	if err != nil || len(res.ips) != maxIPsPerRule {
		t.Fatalf("%d IPs should be accepted, err=%v", maxIPsPerRule, err)
	}
	if _, _, err := parseRewriteTarget(rule(maxIPsPerRule + 1)); err == nil {
		t.Fatalf("%d IPs should be rejected", maxIPsPerRule+1)
	}
}

func newTestRewrite(t *testing.T, rules ...string) *Rewrite {
	m := domain.NewMixMatcher[*rewriteTarget]()
	m.SetDefaultMatcher(domain.MatcherFull)
	if _, err := loadRulesFromReader(strings.NewReader(strings.Join(rules, "\n")), m); err != nil {
		t.Fatal(err)
	}
	return &Rewrite{matcher: m, logger: zap.NewNop()}
}

func exec(t *testing.T, r *Rewrite, name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	qCtx := query_context.NewContext(q)
	if err := r.Exec(context.Background(), qCtx, sequence.ChainWalker{}); err != nil {
		t.Fatal(err)
	}
	return qCtx.R()
}

func answerIPs(r *dns.Msg) []string {
	var ips []string
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A.String())
		case *dns.AAAA:
			ips = append(ips, v.AAAA.String())
		}
	}
	return ips
}

func Test_rewrite_multipleIPs(t *testing.T) {
	r := newTestRewrite(t,
		"nas.lan 192.168.1.10 2001:db8::10",
		"multi.lan 10.0.0.1 10.0.0.2",
		"v4only.lan 10.0.0.3",
	)
	tests := []struct {
		name  string
		qtype uint16
		want  []string // nil = empty response
	}{
		{"nas.lan.", dns.TypeA, []string{"192.168.1.10"}},
		{"nas.lan.", dns.TypeAAAA, []string{"2001:db8::10"}},
		{"nas.lan.", dns.TypeMX, nil},
		{"multi.lan.", dns.TypeA, []string{"10.0.0.1", "10.0.0.2"}},
		{"multi.lan.", dns.TypeAAAA, nil},
		{"v4only.lan.", dns.TypeA, []string{"10.0.0.3"}},
		{"v4only.lan.", dns.TypeAAAA, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name+dns.TypeToString[tt.qtype], func(t *testing.T) {
			resp := exec(t, r, tt.name, tt.qtype)
			if resp == nil {
				t.Fatal("no response")
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode %d", resp.Rcode)
			}
			if got := answerIPs(resp); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("want %v, got %v", tt.want, got)
			}
			for _, rr := range resp.Answer {
				if rr.Header().Ttl != fixedTTL {
					t.Fatalf("ttl %d", rr.Header().Ttl)
				}
			}
		})
	}

	if resp := exec(t, r, "other.lan.", dns.TypeA); resp != nil {
		t.Fatalf("unmatched domain should pass through, got %v", resp)
	}
}

func Test_duplicateDomains(t *testing.T) {
	got := duplicateDomains([]string{
		"a.com 1.1.1.1",
		"b.com 2.2.2.2",
		"A.com. ::1",
		"full:a.com 3.3.3.3",
		"domain:b.com 4.4.4.4", // different matcher, not a duplicate of b.com
		"c.com 5.5.5.5",
		"c.com ::5",
	})
	if want := []string{"a.com", "c.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func Test_warnDuplicateDomains(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	r := &Rewrite{logger: zap.New(core)}
	r.warnDuplicateDomains([]string{"nas.lan 192.168.1.10", "nas.lan 2001:db8::10", "ok.lan 10.0.0.1"})
	entries := logs.All()
	if len(entries) != 1 || !strings.Contains(entries[0].Message, "nas.lan") {
		t.Fatalf("want one warning about nas.lan, got %v", entries)
	}
}
