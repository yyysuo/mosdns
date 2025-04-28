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

package ip_set

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/sagernet/sing/common/varbin"
	"go4.org/netipx"
)

const PluginType = "ip_set"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewIPSet(bp, args.(*Args))
}

// Args holds the configuration for ip_set plugin
type Args struct {
	IPs   []string `yaml:"ips"`
	Sets  []string `yaml:"sets"`
	Files []string `yaml:"files"`
}

var _ data_provider.IPMatcherProvider = (*IPSet)(nil)

// IPSet implements IPMatcherProvider
type IPSet struct {
	mg []netlist.Matcher
}

// GetIPMatcher returns the combined matcher
func (d *IPSet) GetIPMatcher() netlist.Matcher {
	return MatcherGroup(d.mg)
}

// NewIPSet creates a new IPSet, loading plain IPs, files (text or .srs), then referenced sets.
func NewIPSet(bp *coremain.BP, args *Args) (*IPSet, error) {
	p := &IPSet{}

	// load IPs and files
	l := netlist.NewList()
	if err := LoadFromIPsAndFiles(args.IPs, args.Files, l); err != nil {
		return nil, err
	}
	l.Sort()
	if l.Len() > 0 {
		p.mg = append(p.mg, l)
	}

	// load other sets by tag
	for _, tag := range args.Sets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.IPMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not an IPMatcherProvider", tag)
		}
		p.mg = append(p.mg, provider.GetIPMatcher())
	}

	return p, nil
}

// LoadFromIPsAndFiles loads plain IPs and files (including .srs) into the list.
func LoadFromIPsAndFiles(ips []string, files []string, l *netlist.List) error {
	return loadFromIPsAndFiles(ips, files, l)
}

func parseNetipPrefix(s string) (netip.Prefix, error) {
	// parse CIDR or single IP
	if strings.ContainsRune(s, '/') {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	pfx, err := addr.Prefix(addr.BitLen())
	if err != nil {
		return netip.Prefix{}, err
	}
	return pfx, nil
}

func loadFromIPsAndFiles(ips, files []string, l *netlist.List) error {
	if err := loadFromIPs(ips, l); err != nil {
		return err
	}
	return loadFromFiles(files, l)
}

func loadFromIPs(ips []string, l *netlist.List) error {
	for i, s := range ips {
		pfx, err := parseNetipPrefix(s)
		if err != nil {
			return fmt.Errorf("invalid ip #%d %s: %w", i, s, err)
		}
		l.Append(pfx)
	}
	return nil
}

func loadFromFiles(files []string, l *netlist.List) error {
	for i, f := range files {
		if err := loadFromFile(f, l); err != nil {
			return fmt.Errorf("failed to load file #%d %s: %w", i, f, err)
		}
	}
	return nil
}

func loadFromFile(path string, l *netlist.List) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// try .srs binary format first
	if ok, cnt := tryLoadSRS(data, l); ok {
		fmt.Printf("[ip_set] loaded %d rules from srs file: %s\n", cnt, path)
		return nil
	}

	// fallback to text lines
	before := l.Len()
	if err := netlist.LoadFromReader(l, bytes.NewReader(data)); err != nil {
		return err
	}
	after := l.Len()
	fmt.Printf("[ip_set] loaded %d rules from text file: %s\n", after-before, path)
	return nil
}

// MatcherGroup composes multiple netlist.Matchers
type MatcherGroup []netlist.Matcher

// Match returns true if any sub-matcher matches the address
func (mg MatcherGroup) Match(addr netip.Addr) bool {
	for _, m := range mg {
		if m.Match(addr) {
			return true
		}
	}
	return false
}

// --- SRS binary parsing ---

var (
	srsMagic            = [3]byte{'S', 'R', 'S'}
	ruleItemIPCIDR      = uint8(6) // index for IPCIDR in SRS format
	ruleItemFinal       = uint8(0xFF)
	maxSupportedVersion = uint8(3)
)

// tryLoadSRS attempts to parse data as an SRS file and load IPCIDR entries.
func tryLoadSRS(data []byte, l *netlist.List) (bool, int) {
	r := bytes.NewReader(data)
	var mb [3]byte
	if _, err := io.ReadFull(r, mb[:]); err != nil || mb != srsMagic {
		return false, 0
	}
	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil || version > maxSupportedVersion {
		return false, 0
	}
	zr, err := zlib.NewReader(r)
	if err != nil {
		return false, 0
	}
	defer zr.Close()
	br := bufio.NewReader(zr)

	length, err := binary.ReadUvarint(br)
	if err != nil {
		return false, 0
	}
	count := 0
	for i := uint64(0); i < length; i++ {
		count += readRule(br, l)
	}
	return true, count
}

// readRule reads one rule; recurses into logical blocks if needed.
func readRule(r *bufio.Reader, l *netlist.List) int {
	ct := 0
	mode, err := r.ReadByte()
	if err != nil {
		return 0
	}
	switch mode {
	case 0: // default rule
		ct += readDefault(r, l)
	case 1: // logical rule
		_, _ = r.ReadByte()           // skip logical operator
		n, _ := binary.ReadUvarint(r) // number of sub-rules
		for j := uint64(0); j < n; j++ {
			ct += readRule(r, l)
		}
		_, _ = r.ReadByte() // skip invert flag
	}
	return ct
}

// readDefault processes IPCIDR items until final marker.
func readDefault(r *bufio.Reader, l *netlist.List) int {
	count := 0
	for {
		item, err := r.ReadByte()
		if err != nil {
			break
		}
		switch item {
		case ruleItemIPCIDR:
			ipset, err := parseIPSet(r)
			if err != nil {
				return count
			}
			for _, pfx := range ipset.Prefixes() {
				l.Append(pfx)
				count++
			}
		case ruleItemFinal:
			return count
		default:
			return count
		}
	}
	return count
}

// parseIPSet reads a varbin-encoded list of IP ranges and builds an IPSet value.
func parseIPSet(r varbin.Reader) (netipx.IPSet, error) {
	ver, err := r.ReadByte()
	if err != nil {
		return netipx.IPSet{}, err
	}
	if ver != 1 {
		return netipx.IPSet{}, fmt.Errorf("unsupported ipset version: %d", ver)
	}
	var length uint64
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return netipx.IPSet{}, err
	}
	type ipRangeData struct{ From, To []byte }
	ranges := make([]ipRangeData, length)
	if err := varbin.Read(r, binary.BigEndian, &ranges); err != nil {
		return netipx.IPSet{}, err
	}

	var builder netipx.IPSetBuilder
	for _, rr := range ranges {
		from, ok := netip.AddrFromSlice(rr.From)
		if !ok {
			continue
		}
		to, ok := netip.AddrFromSlice(rr.To)
		if !ok {
			continue
		}
		builder.AddRange(netipx.IPRangeFrom(from, to))
	}
	pPtr, err := builder.IPSet()
	if err != nil {
		return netipx.IPSet{}, err
	}
	return *pPtr, nil
}
