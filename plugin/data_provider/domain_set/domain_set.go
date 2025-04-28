package domain_set

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

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

type Args struct {
	Exps  []string `yaml:"exps"`
	Sets  []string `yaml:"sets"`
	Files []string `yaml:"files"`
}

var _ data_provider.DomainMatcherProvider = (*DomainSet)(nil)

type DomainSet struct {
	mg []domain.Matcher[struct{}]
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return MatcherGroup(d.mg)
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewDomainSet(bp, args.(*Args))
}

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

func LoadExpsAndFiles(exps, fs []string, m *domain.MixMatcher[struct{}]) error {
	if err := LoadExps(exps, m); err != nil {
		return err
	}
	return LoadFiles(fs, m)
}

func LoadExps(exps []string, m *domain.MixMatcher[struct{}]) error {
	for i, exp := range exps {
		if err := m.Add(exp, struct{}{}); err != nil {
			return fmt.Errorf("failed to load exp %d %s: %w", i, exp, err)
		}
	}
	return nil
}

func LoadFiles(fs []string, m *domain.MixMatcher[struct{}]) error {
	for i, f := range fs {
		if err := LoadFile(f, m); err != nil {
			return fmt.Errorf("failed to load file %d %s: %w", i, f, err)
		}
	}
	return nil
}

func LoadFile(f string, m *domain.MixMatcher[struct{}]) error {
	if f == "" {
		return nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	if ok, count, last := tryLoadSRS(b, m); ok {
		fmt.Printf("[domain_set] last srs rule: %s\n", last)
		fmt.Printf("[domain_set] loaded %d rules from srs file: %s\n", count, f)
		return nil
	}
	before := m.Len()

	scanner := bufio.NewScanner(bytes.NewReader(b))
	var lastTxt string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lastTxt = line
		}
	}

	if err := domain.LoadFromTextReader[struct{}](m, bytes.NewReader(b), nil); err != nil {
		return err
	}
	after := m.Len()
	fmt.Printf("[domain_set] last txt rule: %s\n", lastTxt)
	fmt.Printf("[domain_set] loaded %d rules from text file: %s\n", after-before, f)
	return nil
}

func tryLoadSRS(b []byte, m *domain.MixMatcher[struct{}]) (bool, int, string) {
	r := bytes.NewReader(b)
	var mb [3]byte
	if _, err := io.ReadFull(r, mb[:]); err != nil || mb != magicBytes {
		return false, 0, ""
	}
	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil || version > ruleSetVersionCurrent {
		return false, 0, ""
	}
	zr, err := zlib.NewReader(r)
	if err != nil {
		return false, 0, ""
	}
	defer zr.Close()
	br := bufio.NewReader(zr)
	length, err := binary.ReadUvarint(br)
	if err != nil {
		return false, 0, ""
	}
	count := 0
	var lastRule string
	for i := uint64(0); i < length; i++ {
		count += readRuleCompat(br, m, &lastRule)
	}
	return true, count, lastRule
}

var (
	magicBytes            = [3]byte{0x53, 0x52, 0x53}
	ruleItemDomain        = uint8(2)
	ruleItemDomainKeyword = uint8(3)
	ruleItemDomainRegex   = uint8(4)
	ruleItemFinal         = uint8(0xFF)
)

const ruleSetVersionCurrent = 3

func readRuleCompat(r *bufio.Reader, m *domain.MixMatcher[struct{}], last *string) int {
	ct := 0
	mode, err := r.ReadByte()
	if err != nil {
		return 0
	}
	switch mode {
	case 0:
		ct += readDefaultRuleCompat(r, m, last)
	case 1:
		_, _ = r.ReadByte()
		n, _ := binary.ReadUvarint(r)
		for i := uint64(0); i < n; i++ {
			ct += readRuleCompat(r, m, last)
		}
		_, _ = r.ReadByte()
	}
	return ct
}

func readDefaultRuleCompat(r *bufio.Reader, m *domain.MixMatcher[struct{}], last *string) int {
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
				*last = "full:" + d
				if m.Add("full:"+d, struct{}{}) == nil {
					count++
				}
			}
			for _, d := range suffix {
				*last = "domain:" + d
				if m.Add("domain:"+d, struct{}{}) == nil {
					count++
				}
			}
		case ruleItemDomainKeyword:
			sl, _ := varbin.ReadValue[[]string](r, binary.BigEndian)
			for _, d := range sl {
				*last = "keyword:" + d
				if m.Add("keyword:"+d, struct{}{}) == nil {
					count++
				}
			}
		case ruleItemDomainRegex:
			sl, _ := varbin.ReadValue[[]string](r, binary.BigEndian)
			for _, d := range sl {
				*last = "regexp:" + d
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
