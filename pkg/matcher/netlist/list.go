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

package netlist

import (
	"fmt"
	"net/netip"
	"sort"
)

// List is a list of netip.Prefix. It stores all netip.Prefix in one single slice
// and uses binary search.
// It is suitable for large static cidr search.
type List struct {
	// stores valid and masked netip.Prefix(s)
	e      []netip.Prefix
	sorted bool
}

// NewList returns an empty *List.
func NewList() *List {
	return &List{
		e: make([]netip.Prefix, 0),
	}
}

func mustValid(l []netip.Prefix) {
	for i, prefix := range l {
		if !prefix.IsValid() {
			panic(fmt.Sprintf("invalid prefix at #%d", i))
		}
	}
}

// Append appends new netip.Prefix(es) to the list.
// Caller must call Sort() before calling Contains() or ForEach().
func (list *List) Append(newNet ...netip.Prefix) {
	for i, n := range newNet {
		addr := to6(n.Addr())
		bits := n.Bits()
		if n.Addr().Is4() {
			bits += 96
		}
		newNet[i] = netip.PrefixFrom(addr, bits).Masked()
	}
	mustValid(newNet)
	list.e = append(list.e, newNet...)
	list.sorted = false
}

// Sort sorts the list and deduplicates contained prefixes.
func (list *List) Sort() {
	if list.sorted {
		return
	}
	sort.Sort(list)
	out := make([]netip.Prefix, 0, len(list.e))
	for i, n := range list.e {
		if i == 0 {
			out = append(out, n)
		} else {
			lv := &out[len(out)-1]
			switch {
			case n.Addr() == lv.Addr():
				if n.Bits() < lv.Bits() {
					*lv = n
				}
			case !lv.Contains(n.Addr()):
				out = append(out, n)
			}
		}
	}
	list.e = out
	list.sorted = true
}

// Len implements sort.Interface.
func (list *List) Len() int {
	return len(list.e)
}

// Less implements sort.Interface.
func (list *List) Less(i, j int) bool {
	return list.e[i].Addr().Less(list.e[j].Addr())
}

// Swap implements sort.Interface.
func (list *List) Swap(i, j int) {
	list.e[i], list.e[j] = list.e[j], list.e[i]
}

// Match reports whether addr is contained in any prefix.
func (list *List) Match(addr netip.Addr) bool {
	return list.Contains(addr)
}

// Contains reports whether the list includes the given netip.Addr.
// Must call Sort() first.
func (list *List) Contains(addr netip.Addr) bool {
	if !list.sorted {
		panic("list is not sorted")
	}
	if !addr.IsValid() {
		return false
	}
	addr = to6(addr)
	i, j := 0, len(list.e)
	for i < j {
		h := int(uint(i+j) >> 1)
		if list.e[h].Addr().Compare(addr) <= 0 {
			i = h + 1
		} else {
			j = h
		}
	}
	if i == 0 {
		return false
	}
	return list.e[i-1].Contains(addr)
}

func (list *List) ForEach(fn func(netip.Prefix)) {
	if !list.sorted {
		panic("netlist.List: must call Sort() before ForEach()")
	}
	for _, p := range list.e {
		fn(p)
	}
}

func to6(addr netip.Addr) netip.Addr {
	if addr.Is6() {
		return addr
	}
	return netip.AddrFrom16(addr.As16())
}
