package switcher2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
)

const PluginType = "switch2"

type Args struct {
	InitialValue string `yaml:"initial_value"`
}

type Switcher2 struct {
	mutex sync.RWMutex
	value string
}

var globalSwitcher2 *Switcher2

func init() {
	sequence.MustRegMatchQuickSetup(PluginType, QuickSetup)
	coremain.RegNewPluginFunc(
		PluginType,
		Init,
		func() any { return new(Args) },
	)
}

func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	sw := &Switcher2{value: cfg.InitialValue}
	globalSwitcher2 = sw
	bp.RegAPI(sw.Api())
	return sw, nil
}

func (s *Switcher2) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	return next.ExecNext(ctx, qCtx)
}

func (s *Switcher2) Api() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/show", func(w http.ResponseWriter, r *http.Request) {
		s.mutex.RLock()
		defer s.mutex.RUnlock()
		io.WriteString(w, s.value)
	})
	r.Post("/post", func(w http.ResponseWriter, r *http.Request) {
		var newVal string
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var body struct{ Value string }
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				newVal = body.Value
			}
		}
		if newVal == "" {
			r.ParseForm()
			newVal = r.FormValue("value")
		}
		s.mutex.Lock()
		s.value = newVal
		s.mutex.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "updated to: %s\n", newVal)
	})
	return r
}

func QuickSetup(_ sequence.BQ, raw string) (sequence.Matcher, error) {
	expected := strings.Trim(raw, `"'`)
	return &switchMatcher2{expected: expected}, nil
}

type switchMatcher2 struct {
	expected string
}

func (m *switchMatcher2) Match(_ context.Context, _ *query_context.Context) (bool, error) {
	if globalSwitcher2 == nil {
		return false, nil
	}
	globalSwitcher2.mutex.RLock()
	defer globalSwitcher2.mutex.RUnlock()
	return globalSwitcher2.value == m.expected, nil
}
