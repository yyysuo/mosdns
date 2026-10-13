package fastforward

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const testUpstreamTimeoutMs = 300

func testReply(t *testing.T, q []byte) []byte {
	m := new(dns.Msg)
	if err := m.Unpack(q); err != nil {
		return nil
	}
	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(1, 2, 3, 4),
	})
	b, err := r.Pack()
	if err != nil {
		t.Error(err)
	}
	return b
}

func testQuery(f *Forward) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	return f.exchange(context.Background(), query_context.NewContext(m), f.us)
}

// udpBlackholeServer replies to every query, except queries from source ports
// in blackhole, which are silently dropped (like a stale NAT mapping).
type udpBlackholeServer struct {
	pc        net.PacketConn
	mu        sync.Mutex
	lastPort  int
	blackhole map[int]bool
}

func newUDPBlackholeServer(t *testing.T) *udpBlackholeServer {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	s := &udpBlackholeServer{pc: pc, blackhole: make(map[int]bool)}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			port := from.(*net.UDPAddr).Port
			s.mu.Lock()
			s.lastPort = port
			drop := s.blackhole[port]
			s.mu.Unlock()
			if drop {
				continue
			}
			if b := testReply(t, buf[:n]); b != nil {
				pc.WriteTo(b, from)
			}
		}
	}()
	return s
}

func (s *udpBlackholeServer) last() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPort
}

func (s *udpBlackholeServer) drop(port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blackhole[port] = true
}

// A timeout must only drop the connection that carried the query. The upstream
// must stay usable and later queries must go through a new connection.
func Test_forward_udpTimeoutReplacesConn(t *testing.T) {
	s := newUDPBlackholeServer(t)
	f, err := NewForward(&Args{Upstreams: []UpstreamConfig{{
		Addr:                 "udp://" + s.pc.LocalAddr().String(),
		UpstreamQueryTimeout: testUpstreamTimeoutMs,
	}}}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	for i := 0; i < 2; i++ {
		if _, err := testQuery(f); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	stalePort := s.last()

	s.drop(stalePort)
	if _, err := testQuery(f); err == nil {
		t.Fatal("query on the blackholed conn should time out")
	}

	for i := 0; i < 3; i++ {
		r, err := testQuery(f)
		if err != nil {
			t.Fatalf("query %d after timeout: %v", i, err)
		}
		if len(r.Answer) != 1 {
			t.Fatalf("query %d after timeout: unexpected answer %v", i, r.Answer)
		}
		if p := s.last(); p == stalePort {
			t.Fatalf("query %d after timeout still sent from the stale port %d", i, p)
		}
	}
}

// Callers that do not ask for it (e.g. aliapi) keep the connection on timeout.
func Test_upstream_timeoutKeepsConnByDefault(t *testing.T) {
	s := newUDPBlackholeServer(t)
	u, err := upstream.NewUpstream("udp://"+s.pc.LocalAddr().String(), upstream.Opt{})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	q, _ := m.Pack()
	exchange := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), testUpstreamTimeoutMs*time.Millisecond)
		defer cancel()
		_, err := u.ExchangeContext(ctx, q)
		return err
	}

	if err := exchange(); err != nil {
		t.Fatal(err)
	}
	port := s.last()
	s.drop(port)
	if err := exchange(); err == nil {
		t.Fatal("query on the blackholed conn should time out")
	}
	_ = exchange()
	if p := s.last(); p != port {
		t.Fatalf("conn was replaced (port %d -> %d) without WithCloseConnOnTimeout", port, p)
	}
}

// A quic connection that stops replying must be replaced after a timeout,
// instead of swallowing queries until its idle timeout.
func Test_forward_quicTimeoutReplacesConn(t *testing.T) {
	l, err := quic.ListenAddr("127.0.0.1:0", testTLSConfig(t), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	var connCount atomic.Int32
	var deadConn atomic.Int32 // index of the conn that stops replying, 0 = none
	go func() {
		for {
			c, err := l.Accept(context.Background())
			if err != nil {
				return
			}
			idx := connCount.Add(1)
			go func() {
				for {
					st, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						defer st.Close()
						var hdr [2]byte
						if _, err := io.ReadFull(st, hdr[:]); err != nil {
							return
						}
						q := make([]byte, binary.BigEndian.Uint16(hdr[:]))
						if _, err := io.ReadFull(st, q); err != nil {
							return
						}
						if deadConn.Load() == idx {
							<-c.Context().Done() // never reply
							return
						}
						b := testReply(t, q)
						out := make([]byte, 2+len(b))
						binary.BigEndian.PutUint16(out, uint16(len(b)))
						copy(out[2:], b)
						st.Write(out)
					}()
				}
			}()
		}
	}()

	f, err := NewForward(&Args{Upstreams: []UpstreamConfig{{
		Addr:                 "quic://" + l.Addr().String(),
		UpstreamQueryTimeout: testUpstreamTimeoutMs,
		InsecureSkipVerify:   true,
	}}}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := testQuery(f); err != nil {
		t.Fatal(err)
	}
	if n := connCount.Load(); n != 1 {
		t.Fatalf("expected 1 conn, got %d", n)
	}

	deadConn.Store(1)
	if _, err := testQuery(f); err == nil {
		t.Fatal("query on the dead conn should time out")
	}

	for i := 0; i < 3; i++ {
		if _, err := testQuery(f); err != nil {
			t.Fatalf("query %d after timeout: %v", i, err)
		}
	}
	if n := connCount.Load(); n != 2 {
		t.Fatalf("expected exactly 1 new conn after timeout, got %d conns", n)
	}
}

func testTLSConfig(t *testing.T) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"doq"},
	}
}
