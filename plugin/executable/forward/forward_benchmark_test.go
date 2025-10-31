package fastforward

import (
    "context"
    "testing"
    "time"

    "github.com/IrineSistiana/mosdns/v5/pkg/pool"
    "github.com/IrineSistiana/mosdns/v5/pkg/query_context"
    "github.com/IrineSistiana/mosdns/v5/pkg/upstream"
    "github.com/miekg/dns"
)

// fakeUpstream is a minimal upstream implementation used for benchmarks.
type fakeUpstream struct{ delay time.Duration }

func (f *fakeUpstream) ExchangeContext(ctx context.Context, m []byte) (*[]byte, error) {
    // Simulate processing delay
    if f.delay > 0 {
        t := time.NewTimer(f.delay)
        select {
        case <-t.C:
        case <-ctx.Done():
            t.Stop()
            return nil, context.Cause(ctx)
        }
    }
    // Build a small A response reusing the original query id/name.
    q := new(dns.Msg)
    _ = q.Unpack(m)
    r := new(dns.Msg)
    r.SetReply(q)
    r.Authoritative = false
    r.RecursionAvailable = true
    if len(q.Question) == 1 {
        name := q.Question[0].Name
        rr := &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{1, 1, 1, 1}}
        r.Answer = append(r.Answer, rr)
    }
    // Pack and return using pool buffer to match production path.
    wire, _ := r.Pack()
    b := pool.GetBuf(len(wire))
    copy(*b, wire)
    return b, nil
}
func (f *fakeUpstream) Close() error { return nil }

// ensure fakeUpstream satisfies interface
var _ upstream.Upstream = (*fakeUpstream)(nil)

func buildForwardForBench(latencies []time.Duration, concurrent int) *Forward {
    f := &Forward{
        args: &Args{Concurrent: concurrent},
        // logger: nil is fine; code guards with zap.NewNop()
        tag2Upstream: make(map[string]*upstreamWrapper),
    }
    for i, d := range latencies {
        uw := &upstreamWrapper{
            u:   &fakeUpstream{delay: d},
            cfg: UpstreamConfig{UpstreamQueryTimeout: int((2 * time.Second).Milliseconds())},
        }
        f.us = append(f.us, uw)
        f.tag2Upstream["u"+string(rune('0'+i))] = uw
    }
    return f
}

func BenchmarkForwardExchange_Parallel(b *testing.B) {
    f := buildForwardForBench([]time.Duration{
        2 * time.Millisecond,
        5 * time.Millisecond,
        8 * time.Millisecond,
    }, 3)

    // Prepare a standard A query
    q := new(dns.Msg)
    q.SetQuestion("example.org.", dns.TypeA)

    b.ReportAllocs()
    b.SetBytes(1)
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            ctx, cancel := context.WithTimeout(context.Background(), time.Second)
            _ = func() error {
                qCtx := query_context.NewContext(q)
                _, err := f.exchange(ctx, qCtx, f.us)
                return err
            }()
            cancel()
        }
    })
}
