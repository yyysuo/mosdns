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
	// Register this plugin type with its initialization funcs. So that, this plugin
	// can be configured by user from configuration file.
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })

	// You can also register a plugin object directly. (If plugin do not need to configure)
	// Then you can directly use "_remove_cname" in configuration file.
	coremain.RegNewPersetPluginFunc("_remove_cname", func(bp *coremain.BP) (any, error) {
		return new(cnameRemover), nil
	})

	// Register a quick setup func for sequence. So that users can
	// init your plugin in the sequence directly in one string.
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

// Args is the arguments of plugin. It will be decoded from yaml.
type Args struct {
	// No specific arguments for removing CNAME records.
}

var _ sequence.Executable = (*cnameRemover)(nil)

// cnameRemover implements handler.ExecutablePlugin.
type cnameRemover struct{}

// Exec implements handler.Executable.
func (c *cnameRemover) Exec(ctx context.Context, qCtx *query_context.Context) error {
	r := qCtx.R()
	if r == nil {
		return nil
	}

	// Filter out CNAME records from the Answer section.
	var filteredAnswer []dns.RR
	for _, rr := range r.Answer {
		if _, ok := rr.(*dns.CNAME); !ok {
			filteredAnswer = append(filteredAnswer, rr)
		}
	}

	// Update the Answer section to remove CNAME records.
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
