package switcher4

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

// PluginType 必须与配置中的 type 保持一致
const PluginType = "switch4"

// Args 用于读取 initial_value
type Args struct {
	InitialValue string `yaml:"initial_value"`
}

// Switcher4 插件实例结构
type Switcher4 struct {
	mutex sync.RWMutex
	value string
}

// 全局单实例变量
var globalSwitcher4 *Switcher4

// 注册插件与 matcher
func init() {
	sequence.MustRegMatchQuickSetup(PluginType, QuickSetup)
	coremain.RegNewPluginFunc(
		PluginType,
		Init,
		func() any { return new(Args) },
	)
}

// Init 创建全局实例并注册 API
func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	sw := &Switcher4{value: cfg.InitialValue}
	globalSwitcher4 = sw

	// 注册 API：/plugins/{tag}/show 和 /post
	bp.RegAPI(sw.Api())
	return sw, nil
}

// Exec 是插件链中的执行方法，此插件不修改 DNS 查询，直接透传
func (s *Switcher4) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	return next.ExecNext(ctx, qCtx)
}

// Api 返回路由器，提供 /show 和 /post 接口
func (s *Switcher4) Api() *chi.Mux {
	r := chi.NewRouter()

	// GET /show 显示当前值
	r.Get("/show", func(w http.ResponseWriter, r *http.Request) {
		s.mutex.RLock()
		defer s.mutex.RUnlock()
		io.WriteString(w, s.value)
	})

	// POST /post 修改值，支持 JSON 和表单
	r.Post("/post", func(w http.ResponseWriter, r *http.Request) {
		var newVal string

		// JSON 方式
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var body struct{ Value string }
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				newVal = body.Value
			}
		}

		// 表单方式
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

// QuickSetup 处理 matches: switch4 'A' 的写法
func QuickSetup(_ sequence.BQ, raw string) (sequence.Matcher, error) {
	expected := strings.Trim(raw, `"'`)
	return &switchMatcher4{expected: expected}, nil
}

// switchMatcher4 做全等匹配
type switchMatcher4 struct {
	expected string
}

func (m *switchMatcher4) Match(_ context.Context, _ *query_context.Context) (bool, error) {
	if globalSwitcher4 == nil {
		return false, nil
	}
	globalSwitcher4.mutex.RLock()
	defer globalSwitcher4.mutex.RUnlock()
	return globalSwitcher4.value == m.expected, nil
}
