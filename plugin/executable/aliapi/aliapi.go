/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package aliapi

import (
	"context" // bytes import removed, not used
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const PluginType = "aliapi"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, quickSetup)
}

const (
	maxConcurrentQueries = 3
	queryTimeout         = time.Second * 5
	defaultAliAPIServer = "223.5.5.5"
)

// Args defines the configuration for the aliapi plugin.
type Args struct {
	Upstreams []UpstreamConfig `yaml:"upstreams"`
	Concurrent int              `yaml:"concurrent"`

	// AliDNS API specific options, global to this plugin instance.
	AccountID       string `yaml:"account_id"`
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	ServerAddr      string `yaml:"server_addr"`
	EcsClientIP     string `yaml:"ecs_client_ip"`
	EcsClientMask   uint8  `yaml:"ecs_client_mask"`

	// Global options for standard DNS upstreams.
	Socks5       string `yaml:"socks5"`
	SoMark       int    `yaml:"so_mark"`
	BindToDevice string `yaml:"bind_to_device"`
	Bootstrap    string `yaml:"bootstrap"`
	BootstrapVer int    `yaml:"bootstrap_version"`
}

// UpstreamConfig defines a single upstream server configuration.
type UpstreamConfig struct {
	Tag               string `yaml:"tag"`
	Addr              string `yaml:"addr"`
	DialAddr          string `yaml:"dial_addr"`
	IdleTimeout       int    `yaml:"idle_timeout"`
	UpstreamQueryTimeout int `yaml:"upstream_query_timeout"`

	Type string `yaml:"type"` // "dns" (default) or "aliapi"

	// Deprecated: This option has no affect.
	// TODO: (v6) Remove this option.
	MaxConns           int  `yaml:"max_conns"`
	EnablePipeline     bool `yaml:"enable_pipeline"`
	EnableHTTP3        bool `yaml:"enable_http3"`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	Socks5       string `yaml:"socks5"`
	SoMark       int    `yaml:"so_mark"`
	BindToDevice string `yaml:"bind_to_device"`
	Bootstrap    string `yaml:"bootstrap"`
	BootstrapVer int    `yaml:"bootstrap_version"`
}

func Init(bp *coremain.BP, args any) (any, error) {
	f, err := NewAliAPI(args.(*Args), Opts{Logger: bp.L(), MetricsTag: bp.Tag()})
	if err != nil {
		return nil, err
	}
	if err := f.RegisterMetricsTo(prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

var _ sequence.Executable = (*AliAPI)(nil)
var _ sequence.QuickConfigurableExec = (*AliAPI)(nil)

// AliAPI represents the aliapi plugin instance.
type AliAPI struct {
	args *Args

	logger       *zap.Logger
	us           []*upstreamWrapper
	tag2Upstream map[string]*upstreamWrapper
}

type Opts struct {
	Logger     *zap.Logger
	MetricsTag string
}

// NewAliAPI inits a AliAPI from given args.
// args must contain at least one upstream.
func NewAliAPI(args *Args, opt Opts) (*AliAPI, error) {
	if len(args.Upstreams) == 0 {
		return nil, errors.New("no upstream is configured")
	}
	if opt.Logger == nil {
		opt.Logger = zap.NewNop()
	}

	if args.ServerAddr == "" {
		args.ServerAddr = defaultAliAPIServer
	}

	f := &AliAPI{
		args:         args,
		logger:       opt.Logger,
		tag2Upstream: make(map[string]*upstreamWrapper),
	}

	applyGlobal := func(c *UpstreamConfig) {
		utils.SetDefaultString(&c.Socks5, args.Socks5)
		utils.SetDefaultUnsignNum(&c.SoMark, args.SoMark)
		utils.SetDefaultString(&c.BindToDevice, args.BindToDevice)
		utils.SetDefaultString(&c.Bootstrap, args.Bootstrap)
		utils.SetDefaultUnsignNum(&c.BootstrapVer, args.BootstrapVer)
		utils.SetDefaultString(&c.Type, "dns")
	}

	for i, c := range args.Upstreams {
		applyGlobal(&c)

		uw := newWrapper(i, c, opt.MetricsTag)
		var u upstream.Upstream
		var err error

		if c.Type == "aliapi" {
			if args.AccountID == "" || args.AccessKeyID == "" || args.AccessKeySecret == "" {
				return nil, fmt.Errorf("aliapi upstream requires account_id, access_key_id, and access_key_secret to be set in plugin args")
			}
			aliAPIArgs := AliAPIUpstreamArgs{
				AccountID:       args.AccountID,
				AccessKeyID:     args.AccessKeyID,
				AccessKeySecret: args.AccessKeySecret,
				ServerAddr:      args.ServerAddr,
				EcsClientIP:     args.EcsClientIP,
				EcsClientMask:   args.EcsClientMask,
			}
			u = NewAliAPIUpstream(aliAPIArgs, opt.Logger)
		} else {
			if len(c.Addr) == 0 {
				return nil, fmt.Errorf("#%d upstream invalid args, addr is required for type 'dns'", i)
			}
			uOpt := upstream.Opt{
				DialAddr:       c.DialAddr,
				Socks5:         c.Socks5,
				SoMark:         c.SoMark,
				BindToDevice:   c.BindToDevice,
				IdleTimeout:    time.Duration(c.IdleTimeout) * time.Second,
				EnablePipeline: c.EnablePipeline,
				EnableHTTP3:    c.EnableHTTP3,
				Bootstrap:      c.Bootstrap,
				BootstrapVer:   c.BootstrapVer,
				TLSConfig: &tls.Config{
					InsecureSkipVerify: c.InsecureSkipVerify,
					ClientSessionCache: tls.NewLRUClientSessionCache(4),
				},
				Logger:        opt.Logger,
				EventObserver: &nopEO{}, // Pass a no-op observer for standard upstreams
			}
			u, err = upstream.NewUpstream(c.Addr, uOpt)
			if err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("failed to init upstream #%d: %w", i, err)
			}
		}

		uw.u = u
		f.us = append(f.us, uw)

		if len(c.Tag) > 0 {
			if _, dup := f.tag2Upstream[c.Tag]; dup {
				_ = f.Close()
				return nil, fmt.Errorf("duplicated upstream tag %s", c.Tag)
			}
			f.tag2Upstream[c.Tag] = uw
		}
	}

	return f, nil
}

func (f *AliAPI) RegisterMetricsTo(r prometheus.Registerer) error {
	for _, wu := range f.us {
		if len(wu.cfg.Tag) == 0 {
			continue
		}
		if err := wu.registerMetricsTo(r); err != nil {
			return err
		}
	}
	return nil
}

func (f *AliAPI) Exec(ctx context.Context, qCtx *query_context.Context) (err error) {
	r, err := f.exchange(ctx, qCtx, f.us)
	if err != nil {
		return err
	}
	qCtx.SetResponse(r)
	return nil
}

// QuickConfigureExec format: [upstream_tag]...
func (f *AliAPI) QuickConfigureExec(args string) (any, error) {
	var us []*upstreamWrapper
	if len(args) == 0 {
		us = f.us
	} else {
		for _, tag := range strings.Fields(args) {
			u := f.tag2Upstream[tag]
			if u == nil {
				return nil, fmt.Errorf("cannot find upstream by tag %s", tag)
			}
			us = append(us, u)
		}
	}
	var execFunc sequence.ExecutableFunc = func(ctx context.Context, qCtx *query_context.Context) error {
		r, err := f.exchange(ctx, qCtx, us)
		if err != nil {
			return err
		}
		qCtx.SetResponse(r)
		return nil
	}
	return execFunc, nil
}

func (f *AliAPI) Close() error {
	for _, u := range f.us {
		_ = u.Close()
	}
	return nil
}

func (f *AliAPI) exchange(ctx context.Context, qCtx *query_context.Context, us []*upstreamWrapper) (*dns.Msg, error) {
	if len(us) == 0 {
		return nil, errors.New("no upstream to exchange")
	}

	queryPayload, err := pool.PackBuffer(qCtx.Q())
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(queryPayload)

	concurrent := f.args.Concurrent
	if concurrent <= 0 {
		concurrent = 1
	}
	if concurrent > maxConcurrentQueries {
		concurrent = maxConcurrentQueries
	}

	type res struct {
		r   *dns.Msg
		err error
	}

	resChan := make(chan res)
	done := make(chan struct{})
	defer close(done)

	var lastValidRes *dns.Msg

	rand.Seed(time.Now().UnixNano())
	r := rand.Intn(len(us))
	
	usToQuery := make([]*upstreamWrapper, 0, concurrent)
	for i := 0; i < concurrent && i < len(us); i++ {
		usToQuery = append(usToQuery, us[(r+i)%len(us)])
	}

	for _, u := range usToQuery {
		qc := copyPayload(queryPayload)

		upstreamTimeout := time.Duration(u.cfg.UpstreamQueryTimeout) * time.Millisecond
		if upstreamTimeout == 0 {
			upstreamTimeout = queryTimeout
		}

		go func(uqid uint32, question dns.Question, currentUpstream *upstreamWrapper) {
			defer pool.ReleaseBuf(qc)
			upstreamCtx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
			defer cancel()

			// Metrics handled by upstreamWrapper directly
			currentUpstream.mQueryTotal.Inc()
			currentUpstream.mInflight.Inc()

			var r *dns.Msg
			respPayload, err := currentUpstream.u.ExchangeContext(upstreamCtx, *qc) // Call wrapped upstream
			if err != nil {
				currentUpstream.mErrorTotal.Inc()
				currentUpstream.mInflight.Dec() // Decrement on error
				// Skip logging "context deadline exceeded" or other common network errors
				if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) &&
					!strings.Contains(err.Error(), "connection refused") &&
					!strings.Contains(err.Error(), "no such host") {
					f.logger.Debug("upstream query failed", zap.String("upstream", currentUpstream.cfg.Addr), zap.Error(err))
				}
			} else {
				currentUpstream.mInflight.Dec() // Decrement on success
				r = new(dns.Msg)
				err = r.Unpack(*respPayload)
				pool.ReleaseBuf(respPayload)
				if err != nil {
					r = nil
					f.logger.Debug("failed to unpack DNS response", zap.String("upstream", currentUpstream.cfg.Addr), zap.Error(err))
				}
			}

			select {
			case resChan <- res{r: r, err: err}:
			case <-done:
			}
		}(qCtx.Id(), qCtx.QQuestion(), u)
	}

	receivedResponses := 0
	for receivedResponses < len(usToQuery) {
		select {
		case res := <-resChan:
			receivedResponses++
			r, err := res.r, res.err
			if err != nil {
				continue
			}

			if len(r.Answer) > 0 {
				for _, ans := range r.Answer {
					if a, ok := ans.(*dns.A); ok && len(a.A) > 0 {
						return r, nil
					}
					if aaaa, ok := ans.(*dns.AAAA); ok && len(aaaa.AAAA) > 0 {
						return r, nil
					}
				}
			}

			if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
				if lastValidRes == nil {
					lastValidRes = r
				} else if r.Rcode == dns.RcodeSuccess {
					if lastValidRes.Rcode != dns.RcodeSuccess {
						lastValidRes = r
					}
				}
			}

		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}

	if lastValidRes != nil {
		return lastValidRes, nil
	}

	return nil, nil
}

func quickSetup(bq sequence.BQ, s string) (any, error) {
	args := new(Args)
	args.Concurrent = maxConcurrentQueries
	for _, u := range strings.Fields(s) {
		args.Upstreams = append(args.Upstreams, UpstreamConfig{Addr: u, Type: "dns"})
	}
	return NewAliAPI(args, Opts{Logger: bq.L()})
}

// DNSEntity represents the structure of the JSON response from AliDNS API
type DNSEntity struct {
	Status int      `json:"status"`
	Answer []Answer `json:"answer"`
	Remark string   `json:"remark"`
}

// Answer represents a single DNS record in the AliDNS API response
type Answer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

// getDNSRecord converts a JSON Answer object to a dns.RR
func getDNSRecord(ans Answer) dns.RR {
	header := dns.RR_Header{Name: ans.Name, Rrtype: ans.Type, Class: dns.ClassINET, Ttl: ans.TTL}
	switch ans.Type {
	case dns.TypeA:
		rr := new(dns.A)
		rr.Hdr = header
		rr.A = net.ParseIP(ans.Data)
		return rr
	case dns.TypeNS:
		rr := new(dns.NS)
		rr.Hdr = header
		rr.Ns = ans.Data
		return rr
	case dns.TypeCNAME:
		rr := new(dns.CNAME)
		rr.Hdr = header
		rr.Target = ans.Data
		return rr
	case dns.TypeSOA:
		rr := new(dns.SOA)
		rr.Hdr = header
		data := strings.Fields(ans.Data)
		if len(data) == 7 {
			rr.Ns = data[0]
			rr.Mbox = data[1]
			rr.Serial = uint32(string2int(data[2]))
			rr.Refresh = uint32(string2int(data[3]))
			rr.Retry = uint32(string2int(data[4]))
			rr.Expire = uint32(string2int(data[5]))
			rr.Minttl = uint32(string2int(data[6]))
		} else {
			return &dns.TXT{Hdr: header, Txt: []string{"Malformed SOA: " + ans.Data}}
		}
		return rr
	case dns.TypeMX:
		rr := new(dns.MX)
		rr.Hdr = header
		data := strings.Fields(ans.Data)
		if len(data) == 2 {
			rr.Preference = uint16(string2int(data[0]))
			rr.Mx = data[1]
		} else {
			return &dns.TXT{Hdr: header, Txt: []string{"Malformed MX: " + ans.Data}}
		}
		return rr
	case dns.TypeTXT:
		rr := new(dns.TXT)
		rr.Hdr = header
		cleanedData := strings.Trim(ans.Data, "\"")
		rr.Txt = []string{cleanedData}
		return rr
	case dns.TypeAAAA:
		rr := new(dns.AAAA)
		rr.Hdr = header
		rr.AAAA = net.ParseIP(ans.Data)
		return rr
	case dns.TypeCAA:
		rr := new(dns.CAA)
		rr.Hdr = header
		data := strings.Fields(ans.Data)
		if len(data) == 3 {
			rr.Flag = uint8(string2int(data[0]))
			rr.Tag = data[1]
			rr.Value = strings.Trim(data[2], "\"")
		} else {
			return &dns.TXT{Hdr: header, Txt: []string{"Malformed CAA: " + ans.Data}}
		}
		return rr
	default:
		rr := new(dns.TXT)
		rr.Hdr = header
		cleanedData := strings.Trim(ans.Data, "\"")
		rr.Txt = []string{fmt.Sprintf("Type %d: %s", ans.Type, cleanedData)}
		return rr
	}
}

// string2int is a helper to convert string to int, unsafe version from AhaDNS
func string2int(str string) int {
	i, _ := strconv.Atoi(str)
	return i
}

// AliAPIUpstreamArgs holds configuration for an AliAPI upstream instance.
type AliAPIUpstreamArgs struct {
	AccountID       string
	AccessKeyID     string
	AccessKeySecret string
	ServerAddr      string
	EcsClientIP     string
	EcsClientMask   uint8
}

// AliAPIUpstream implements the upstream.Upstream interface for AliDNS JSON API.
// It no longer takes an EventObserver.
type AliAPIUpstream struct {
	args     AliAPIUpstreamArgs
	logger   *zap.Logger
	client   *http.Client
}

// NewAliAPIUpstream creates a new AliAPIUpstream.
func NewAliAPIUpstream(args AliAPIUpstreamArgs, logger *zap.Logger) *AliAPIUpstream {
	httpClient := &http.Client{
		Timeout: 0,
	}
	return &AliAPIUpstream{
		args:     args,
		logger:   logger,
		client:   httpClient,
	}
}

// ExchangeContext performs a DNS query via AliDNS JSON API.
func (a *AliAPIUpstream) ExchangeContext(ctx context.Context, req []byte) (resp *[]byte, err error) {
	dnsMsg := new(dns.Msg)
	if err := dnsMsg.Unpack(req); err != nil {
		a.logger.Warn("failed to unpack DNS message for AliAPI", zap.Error(err))
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	if len(dnsMsg.Question) == 0 {
		return nil, errors.New("DNS message has no questions")
	}

	q := dnsMsg.Question[0]
	qName := dns.Fqdn(q.Name)
	qType := dns.Type(q.Qtype).String()

	responseMsg := new(dns.Msg)
	responseMsg.SetReply(dnsMsg)
	responseMsg.Authoritative = true

	var ednsClientSubnet string
	if a.args.EcsClientIP != "" && a.args.EcsClientMask > 0 {
		ednsClientSubnet = fmt.Sprintf("%s/%d", a.args.EcsClientIP, a.args.EcsClientMask)
	} else {
		for _, opt := range dnsMsg.Extra {
			if edns0, ok := opt.(*dns.OPT); ok {
				for _, option := range edns0.Option {
					if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
						ednsClientSubnet = ecs.Address.String() + "/" + strconv.Itoa(int(ecs.SourceNetmask))
						break
					}
				}
			}
			if ednsClientSubnet != "" {
				break
			}
		}
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	keyData := a.args.AccountID + a.args.AccessKeySecret + ts + qName + a.args.AccessKeyID
	keyHash := sha256.Sum256([]byte(keyData))
	keyStr := hex.EncodeToString(keyHash[:])

	url := fmt.Sprintf("http://%s/resolve?name=%s&type=%s&uid=%s&ak=%s&key=%s&ts=%s",
		a.args.ServerAddr, qName, qType, a.args.AccountID, a.args.AccessKeyID, keyStr, ts)
	if ednsClientSubnet != "" {
		url = fmt.Sprintf("%s&edns_client_subnet=%s", url, ednsClientSubnet)
	}

	a.logger.Debug("Requesting AliDNS JSON API", zap.String("url", url))
	httpReq, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	httpResp, httpErr := a.client.Do(httpReq)
	if httpErr != nil {
		a.logger.Debug("AliAPI HTTP request failed", zap.String("url", url), zap.Error(httpErr))
		return nil, fmt.Errorf("AliAPI HTTP request failed: %w", httpErr)
	}
	defer httpResp.Body.Close()

	body, readErr := io.ReadAll(httpResp.Body)
	if readErr != nil {
		a.logger.Warn("Failed to read AliAPI response body", zap.Error(readErr))
		return nil, fmt.Errorf("failed to read AliAPI response body: %w", readErr)
	}

	a.logger.Debug("AliAPI raw response", zap.String("body", string(body)))

	var aliDNSResult DNSEntity
	jsonErr := json.Unmarshal(body, &aliDNSResult)
	if jsonErr != nil {
		a.logger.Warn("Failed to unmarshal AliAPI JSON response", zap.Error(jsonErr), zap.String("body", string(body)))
		return nil, fmt.Errorf("failed to unmarshal AliAPI JSON response: %w", jsonErr)
	}

	if aliDNSResult.Status != 0 {
		responseMsg.SetRcode(responseMsg, dns.RcodeServerFailure)
		a.logger.Warn("AliAPI returned error status", zap.Int("status", aliDNSResult.Status), zap.String("remark", aliDNSResult.Remark))
		packed, packErr := pool.PackBuffer(responseMsg)
		if packErr != nil {
			return nil, fmt.Errorf("failed to pack AliAPI error response: %w", packErr)
		}
		return packed, fmt.Errorf("AliAPI query failed: status %d, remark: %s", aliDNSResult.Status, aliDNSResult.Remark)
	}

	for _, ans := range aliDNSResult.Answer {
		if ans.Name == qName {
			record := getDNSRecord(ans)
			responseMsg.Answer = append(responseMsg.Answer, record)
		}
	}

	if len(responseMsg.Answer) == 0 {
		responseMsg.SetRcode(responseMsg, dns.RcodeNameError)
	} else {
		responseMsg.SetRcode(responseMsg, dns.RcodeSuccess)
	}

	packed, packErr := pool.PackBuffer(responseMsg)
	if packErr != nil {
		return nil, fmt.Errorf("failed to pack DNS response from AliAPI result: %w", packErr)
	}
	return packed, nil
}

// Close for AliAPIUpstream is a no-op as there are no persistent connections.
func (a *AliAPIUpstream) Close() error {
	return nil
}

// --- EventObserver placeholder for standard upstreams ---
// This is a minimal EventObserver that does nothing. It's used when we
// create standard `upstream.Upstream` instances, because the metrics
// will now be handled directly by `upstreamWrapper.ExchangeContext`.
type nopEO struct{}

func (nopEO) OnEvent(upstream.Event) {}


// upstreamWrapper wraps an upstream.Upstream and collects metrics.
type upstreamWrapper struct {
	u          upstream.Upstream
	cfg        UpstreamConfig
	metricsTag string

	mQueryTotal prometheus.Counter
	mErrorTotal prometheus.Counter
	mInflight   prometheus.Gauge
}

func newWrapper(idx int, c UpstreamConfig, metricsTag string) *upstreamWrapper {
	return &upstreamWrapper{
		cfg:        c,
		metricsTag: fmt.Sprintf("%s_%d", metricsTag, idx),
		mQueryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "query_total",
			Help: "Total number of queries.",
			ConstLabels: prometheus.Labels{
				"tag": c.Tag,
				"addr": c.Addr,
				"metrics_tag": metricsTag,
			},
		}),
		mErrorTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "error_total",
			Help: "Total number of query errors.",
			ConstLabels: prometheus.Labels{
				"tag": c.Tag,
				"addr": c.Addr,
				"metrics_tag": metricsTag,
			},
		}),
		mInflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "inflight_queries",
			Help: "Number of inflight queries.",
			ConstLabels: prometheus.Labels{
				"tag": c.Tag,
				"addr": c.Addr,
				"metrics_tag": metricsTag,
			},
		}),
	}
}

// ExchangeContext handles the actual exchange and updates metrics directly.
// This method takes over the responsibility of calling metric updates,
// thus `u` (the wrapped upstream) no longer needs to call them via EventObserver.
func (w *upstreamWrapper) ExchangeContext(ctx context.Context, req []byte) (*[]byte, error) {
	w.mQueryTotal.Inc()
	w.mInflight.Inc()

	resp, err := w.u.ExchangeContext(ctx, req) // Call the wrapped upstream's method

	w.mInflight.Dec() // Always decrement inflight after the exchange completes

	if err != nil {
		w.mErrorTotal.Inc()
	}

	return resp, err
}

func (w *upstreamWrapper) Close() error {
	return w.u.Close()
}

func (w *upstreamWrapper) registerMetricsTo(r prometheus.Registerer) error {
	if err := r.Register(w.mQueryTotal); err != nil {
		return err
	}
	if err := r.Register(w.mErrorTotal); err != nil {
		return err
	}
	if err := r.Register(w.mInflight); err != nil {
		return err
	}
	return nil
}

func copyPayload(p *[]byte) *[]byte {
	buf := pool.GetBuf(len(*p))
	copy(*buf, *p)
	return buf
}
