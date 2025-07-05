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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
 
package cname_remover

import (
	"context"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "cname_remover"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	coremain.RegNewPersetPluginFunc("_remove_cname", func(bp *coremain.BP) (any, error) {
		return new(cnameRemover), nil
	})
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

// Args is the arguments of plugin. It will be decoded from yaml.
type Args struct {
	// No specific arguments for removing CNAME records.
}

var _ sequence.Executable = (*cnameRemover)(nil)

// cnameRemover implements handler.ExecutablePlugin.
type cnameRemover struct{}

// Exec 实现了核心处理逻辑.
// 这个版本是经过优化的，并且只处理 A 和 AAAA 查询.
func (c *cnameRemover) Exec(ctx context.Context, qCtx *query_context.Context) error {
	r := qCtx.R()
	if r == nil || len(r.Answer) == 0 {
		return nil
	}

	// ==================== 变更点 1: 限定查询类型 ====================
	// 检查查询类型，如果不是 A 或 AAAA，则直接返回，不进行任何操作。
	qType := qCtx.QQuestion().Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil
	}
	// =============================================================

	qName := qCtx.QQuestion().Name

	// ==================== 变更点 2: 高效的切片操作 ====================
	// 创建一个新切片头 `filteredAnswer`，它重用 `r.Answer` 的底层数组。
	// 这避免了为新切片分配内存，从而提高了性能。
	filteredAnswer := r.Answer[:0]
	// =============================================================

	// 遍历响应中的所有记录。这个逻辑不依赖于记录的顺序，非常健壮。
	for _, rr := range r.Answer {
		// 检查记录类型是否为 CNAME。
		// 使用 rr.Header().Rrtype 而不是类型断言，可以覆盖所有 CNAME-like 的记录。
		if rr.Header().Rrtype == dns.TypeCNAME {
			continue // 如果是 CNAME，则跳过，即“移除”它。
		}

		// 如果不是 CNAME，说明是我们想要保留的记录 (如 A, AAAA)。
		// 将其域名头修改为原始查询的域名，以确保响应的逻辑一致性。
		rr.Header().Name = qName
		// 将修改后的记录添加到 filteredAnswer 中。
		filteredAnswer = append(filteredAnswer, rr)
	}

	// 用我们处理过的、不含 CNAME 的记录列表替换原始的 Answer 部分。
	r.Answer = filteredAnswer
	return nil
}

func Init(_ *coremain.BP, args any) (any, error) {
	// No arguments needed for removing CNAME records.
	return new(cnameRemover), nil
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	// This plugin does not require configuration via quick setup.
	return new(cnameRemover), nil
}
