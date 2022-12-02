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

package base_ip

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"net/netip"
	"strings"
)

var _ sequence.Matcher = (*Matcher)(nil)

type FileArgs = ip_set.FileArgs
type Args struct {
	IPs    []string `yaml:"ips"`
	IPSets []string `yaml:"ip_sets"`
	Files  []string `yaml:"files"`
}

type MatchFunc func(qCtx *query_context.Context, m AddrMatcher) (bool, error)

type Matcher struct {
	sequence.BQ
	match MatchFunc

	mg []netlist.Matcher
}

func (m *Matcher) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return m.match(qCtx, m.mg)
}

func NewMatcher(bq sequence.BQ, args *Args, f MatchFunc) (m *Matcher, err error) {
	m = &Matcher{
		BQ:    bq,
		match: f,
	}

	// Acquire lists from other plugins or files.
	for _, tag := range args.IPSets {
		p := bq.M().GetPlugins(tag)
		provider, _ := p.(ip_set.IPSetProvider)
		if provider == nil {
			return nil, fmt.Errorf("cannot find ipset %s", tag)
		}
		l := provider.GetIPSet()
		m.mg = append(m.mg, l)
	}

	// Anonymous set from plugin's args and files.
	anonymousList := netlist.NewList()
	if err := ip_set.LoadFromIPs(args.IPs, anonymousList); err != nil {
		return nil, err
	}
	for _, path := range args.Files {
		if err := ip_set.LoadFromFile(ip_set.FileArgs{Path: path}, anonymousList); err != nil {
			return nil, fmt.Errorf("failed to load ip list from file %s, %w", path, err)
		}
	}
	anonymousList.Sort()

	if anonymousList.Len() > 0 {
		m.mg = append(m.mg, anonymousList)
	}
	return m, nil
}

// ParseQuickSetupArgs parses expressions and "ip_set"s to args.
// Format: "([ip] | [$ip_set_tag] | [&ip_list_file])..."
func ParseQuickSetupArgs(s string) *Args {
	cutPrefix := func(s string, p string) (string, bool) {
		if strings.HasPrefix(s, p) {
			return strings.TrimPrefix(s, p), true
		}
		return s, false
	}

	args := new(Args)
	for _, exp := range strings.Fields(s) {
		if tag, ok := cutPrefix(exp, "$"); ok {
			args.IPSets = append(args.IPSets, tag)
		} else if path, ok := cutPrefix(exp, "&"); ok {
			args.Files = append(args.Files, path)
		} else {
			args.IPs = append(args.IPs, exp)
		}
	}
	return args
}

type AddrMatcher []netlist.Matcher

func (m AddrMatcher) Match(addr netip.Addr) bool {
	for _, m := range m {
		if m.Match(addr) {
			return true
		}
	}
	return false
}