package switcher1

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "sync"

    "github.com/IrineSistiana/mosdns/v5/coremain"
    "github.com/IrineSistiana/mosdns/v5/pkg/query_context"
    "github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
    "github.com/go-chi/chi/v5"
)

const PluginType = "switch1"

// Args 里的 initial_value 现在当作「状态文件路径」
type Args struct {
    InitialValue string `yaml:"initial_value"`
}

type Switcher1 struct {
    mutex    sync.RWMutex
    value    string
    filePath string
}

var globalSwitcher1 *Switcher1

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
    sw := &Switcher1{
        filePath: cfg.InitialValue,
    }
    // 确保目录存在
    if err := os.MkdirAll(filepath.Dir(sw.filePath), 0755); err != nil {
        return nil, fmt.Errorf("cannot create dir for switch1 file: %w", err)
    }
    // 读取已有状态
    data, err := os.ReadFile(sw.filePath)
    if err == nil {
        sw.value = strings.TrimSpace(string(data))
    } else {
        // 如果文件不存在，就写入一个默认空值
        sw.value = ""
        _ = os.WriteFile(sw.filePath, []byte(sw.value), 0644)
    }

    globalSwitcher1 = sw
    bp.RegAPI(sw.Api())
    return sw, nil
}

func (s *Switcher1) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
    return next.ExecNext(ctx, qCtx)
}

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
        // 更新内存
        s.mutex.Lock()
        s.value = newVal
        s.mutex.Unlock()
        // 持久化到文件
        if err := os.WriteFile(s.filePath, []byte(newVal), 0644); err != nil {
            http.Error(w, "failed to write switch file: "+err.Error(), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, "updated to: %s\n", newVal)
    })

    return r
}

func QuickSetup(_ sequence.BQ, raw string) (sequence.Matcher, error) {
    expected := strings.Trim(raw, `"'`)
    return &switchMatcher1{expected: expected}, nil
}

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
