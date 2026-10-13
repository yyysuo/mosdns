package fast_mark

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"go.uber.org/zap"
)

const PluginType = "fast_mark"

func init() {
	// 注册为 Exec 插件 (用于设置 Flag)
	coremain.RegNewPluginFunc(PluginType, func(bp *coremain.BP, args any) (any, error) {
		// 这里虽然用了 args 接口，但在 sequence 中通常直接用 QuickSetup 
		// 为了兼容标准插件加载流程，这里做一个简单的包装
		return newFastMarker(*args.(*string), bp.L())
	}, func() any { return new(string) })

	// 注册 sequence QuickSetup (支持 exec: fast_mark 1)
	sequence.MustRegExecQuickSetup(PluginType, func(bq sequence.BQ, args string) (any, error) {
		return newFastMarker(args, bq.L())
	})

	// 注册 sequence Matcher QuickSetup (支持 matches: fast_mark 1)
	sequence.MustRegMatchQuickSetup(PluginType, func(bq sequence.BQ, args string) (sequence.Matcher, error) {
		return newFastMarker(args, bq.L())
	})
}

var _ sequence.Executable = (*fastMark)(nil)
var _ sequence.Matcher = (*fastMark)(nil)

type fastMark struct {
	flags []uint8
}

// Match 实现了 sequence.Matcher 接口
// 逻辑：检查是否包含配置中的【任意一个】Flag (OR 逻辑)
func (m *fastMark) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
	for _, f := range m.flags {
		// [极速] 位运算检查，耗时 < 2ns
		if qCtx.HasFastFlag(f) {
			return true, nil
		}
	}
	return false, nil
}

// Exec 实现了 sequence.Executable 接口
// 逻辑：设置配置中的【所有】Flag
func (m *fastMark) Exec(_ context.Context, qCtx *query_context.Context) error {
	for _, f := range m.flags {
		// [极速] 位运算设置，耗时 < 2ns
		qCtx.SetFastFlag(f)
	}
	return nil
}

// newFastMarker 解析参数字符串，支持多个 Flag，例如 "1 2 5"
func newFastMarker(s string, logger *zap.Logger) (*fastMark, error) {
	var flags []uint8
	for _, ms := range strings.Fields(s) {
		n, err := strconv.ParseUint(ms, 10, 8) // 解析为 uint8
		if err != nil {
			return nil, fmt.Errorf("invalid fast_mark ID '%s': %w", ms, err)
		}
		if n > 63 {
			return nil, fmt.Errorf("fast_mark ID must be between 0 and 63, got %d", n)
		}
		if sw := query_context.SwitchOfFastFlag(uint8(n)); sw != 0 {
			// Not rejected, so configs that already use it keep working.
			logger.Warn(fmt.Sprintf("fast_mark ID %d collides with the switch%d state bit (32-47 are reserved for switch states): "+
				"as a matcher it follows switch%d, as an action it changes switch%d for this query. "+
				"Pick another ID, or use the switch%d matcher to check the switch state", n, sw, sw, sw, sw))
		}
		flags = append(flags, uint8(n))
	}
	
	if len(flags) == 0 {
		return nil, fmt.Errorf("fast_mark requires at least one ID")
	}

	return &fastMark{flags: flags}, nil
}

func (m *fastMark) GetFastCheck() func(qCtx *query_context.Context) bool {
	fList := m.flags
	return func(qCtx *query_context.Context) bool {
		for _, f := range fList {
			if qCtx.HasFastFlag(f) { return true }
		}
		return false
	}
}

func (m *fastMark) GetFastExec() func(context.Context, *query_context.Context) error {
	fList := m.flags // 闭包逃逸优化
	return func(_ context.Context, qCtx *query_context.Context) error {
		for _, f := range fList {
			qCtx.SetFastFlag(f)
		}
		return nil
	}
}
