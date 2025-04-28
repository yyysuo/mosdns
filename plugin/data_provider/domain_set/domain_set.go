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

package domain_set

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"

	scdomain "github.com/sagernet/sing/common/domain"
	"github.com/sagernet/sing/common/varbin"
)

const PluginType = "domain_set"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

// Args holds plugin configuration
type Args struct {
	Exps  []string `yaml:"exps"`
	Sets  []string `yaml:"sets"`
	Files []string `yaml:"files"`
}

var _ data_provider.DomainMatcherProvider = (*DomainSet)(nil)

// DomainSet implements DomainMatcherProvider
type DomainSet struct {
	mg []domain.Matcher[struct{}]
}

// GetDomainMatcher returns combined matcher
func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return MatcherGroup(d.mg)
}

// Init initializes the plugin
func Init(bp *coremain.BP, args any) (any, error) {
	return NewDomainSet(bp, args.(*Args))
}

// NewDomainSet creates matcher group from args
func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	d := &DomainSet{}
	m := domain.NewDomainMixMatcher()
	if err := LoadExpsAndFiles(args.Exps, args.Files, m); err != nil {
		return nil, err
	}
	if m.Len() > 0 {
		d.mg = append(d.mg, m)
	}
	for _, tag := range args.Sets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		d.mg = append(d.mg, provider.GetDomainMatcher())
	}
	return d, nil
}

// LoadExpsAndFiles loads expressions and files
func LoadExpsAndFiles(exps, fs []string, m *domain.MixMatcher[struct{}]) error {
	if err := LoadExps(exps, m); err != nil {
		return err
	}
	return LoadFiles(fs, m)
}

// LoadExps loads expression list
func LoadExps(exps []string, m *domain.MixMatcher[struct{}]) error {
	for i, exp := range exps {
		if err := m.Add(exp, struct{}{}); err != nil {
			return fmt.Errorf("failed to load exp %d %s: %w", i, exp, err)
		}
	}
	return nil
}

// LoadFiles loads files from given paths
func LoadFiles(fs []string, m *domain.MixMatcher[struct{}]) error {
	for i, f := range fs {
		if err := LoadFile(f, m); err != nil {
			return fmt.Errorf("failed to load file %d %s: %w", i, f, err)
		}
	}
	return nil
}

// LoadFile loads a single file; supports text and SRS binary
func LoadFile(f string, m *domain.MixMatcher[struct{}]) error {
	if f == "" {
		return nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	// Try SRS format first
	if ok, count := tryLoadSRS(b, m); ok {
		fmt.Printf("[domain_set] loaded %d rules from srs file: %s\n", count, f)
		return nil
	}
	// Fallback to text format
	before := m.Len()
	if err := domain.LoadFromTextReader[struct{}](m, bytes.NewReader(b), nil); err != nil {
		return err
	}
	after := m.Len()
	fmt.Printf("[domain_set] loaded %d rules from text file: %s\n", after-before, f)
	return nil
}

// --- SRS parsing (inlined, no sing-box dependency) ---

var (
	magicBytes            = [3]byte{0x53, 0x52, 0x53} // "SRS"
	ruleItemDomain        = uint8(2)
	ruleItemDomainKeyword = uint8(3)
	ruleItemDomainRegex   = uint8(4)
	ruleItemFinal         = uint8(0xFF)
)

const ruleSetVersionCurrent = 3

// tryLoadSRS parses SRS binary, extracts domain rules
func tryLoadSRS(b []byte, m *domain.MixMatcher[struct{}]) (bool, int) {
	r := bytes.NewReader(b)
	// magic
	var mb [3]byte
	if _, err := io.ReadFull(r, mb[:]); err != nil || mb != magicBytes {
		return false, 0
	}
	// version
	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil || version > ruleSetVersionCurrent {
		return false, 0
	}
	// decompress
	zr, err := zlib.NewReader(r)
	if err != nil {
		return false, 0
	}
	defer zr.Close()
	br := bufio.NewReader(zr)
	// rules count
	length, err := binary.ReadUvarint(br)
	if err != nil {
		return false, 0
	}
	count := 0
	for i := uint64(0); i < length; i++ {
		count += readRuleCompat(br, m)
	}
	return true, count
}

// readRuleCompat reads a headless rule and extracts domains
func readRuleCompat(r *bufio.Reader, m *domain.MixMatcher[struct{}]) int {
	ct := 0
	mode, err := r.ReadByte()
	if err != nil {
		return 0
	}
	switch mode {
	case 0: // default rule
		ct += readDefaultRuleCompat(r, m)
	case 1: // logical rule
		// skip logical mode
		_, _ = r.ReadByte()
		// sub-rules count
		n, _ := binary.ReadUvarint(r)
		for i := uint64(0); i < n; i++ {
			ct += readRuleCompat(r, m)
		}
		// skip invert
		_, _ = r.ReadByte()
	}
	return ct
}

// readDefaultRuleCompat reads default rule items
func readDefaultRuleCompat(r *bufio.Reader, m *domain.MixMatcher[struct{}]) int {
	count := 0
	for {
		item, err := r.ReadByte()
		if err != nil {
			break
		}
		switch item {
		case ruleItemDomain:
			matcher, err := scdomain.ReadMatcher(r)
			if err != nil {
				return count
			}
			doms, suffix := matcher.Dump()
			for _, d := range doms {
				if m.Add(d, struct{}{}) == nil {
					count++
				}
			}
			for _, d := range suffix {
				if m.Add("*."+d, struct{}{}) == nil {
					count++
				}
			}
		case ruleItemDomainKeyword:
			sl, _ := varbin.ReadValue[[]string](r, binary.BigEndian)
			for _, d := range sl {
				if m.Add("keyword:"+d, struct{}{}) == nil {
					count++
				}
			}
		case ruleItemDomainRegex:
			sl, _ := varbin.ReadValue[[]string](r, binary.BigEndian)
			for _, d := range sl {
				if m.Add("regexp:"+d, struct{}{}) == nil {
					count++
				}
			}
		case ruleItemFinal:
			return count
		default:
			return count
		}
	}
	return count
}
