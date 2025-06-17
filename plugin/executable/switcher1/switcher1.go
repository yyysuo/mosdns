package switcher1 // ✅ 1. 修改包名

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

// ✅ 2. 修改插件类型名（对应配置中的 type: switch1）
const PluginType = "switch1"

// ✅ 3. Args 结构体无需更动
type Args struct {
	InitialValue string `yaml:"initial_value"`
}

// ✅ 4. 改名为 Switcher1，避免与 switcher 冲突
type Switcher1 struct {
	mutex sync.RWMutex
	value string
}

// ✅ 5. 改为独立的全局变量
var globalSwitcher1 *Switcher1

// ✅ 6. 注册插件与 matcher（使用 switch1 类型）
func init() {
	sequence.MustRegMatchQuickSetup(PluginType, QuickSetup)
	coremain.RegNewPluginFunc(
		PluginType,
		Init,
		func() any { return new(Args) },
	)
}

// ✅ 7. Init 创建实例并注册 API
func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	sw := &Switcher1{value: cfg.InitialValue}
	globalSwitcher1 = sw

	bp.RegAPI(sw.Api())
	return sw, nil
}

// ✅ 8. Exec 方法
func (s *Switcher1) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	return next.ExecNext(ctx, qCtx)
}

// ✅ 9. API 实现
func (s *Switcher1) Api() *chi.Mux {
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

// ✅ 10. Matcher 快速配置
func QuickSetup(_ sequence.BQ, raw string) (sequence.Matcher, error) {
	expected := strings.Trim(raw, `"'`)
	return &switchMatcher1{expected: expected}, nil
}

// ✅ 11. 独立 matcher 结构
type switchMatcher1 struct {
	expected string
}

func (m *switchMatcher1) Match(_ context.Context, _ *query_context.Context) (bool, error) {
	if globalSwitcher1 == nil {
		return false, nil
	}
	globalSwitcher1.mutex.RLock()
	defer globalSwitcher1.mutex.RUnlock()
	return globalSwitcher1.value == m.expected, nil
}
