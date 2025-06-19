package domain_set

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	scdomain "github.com/sagernet/sing/common/domain"
	"github.com/sagernet/sing/common/varbin"
	"github.com/go-chi/chi/v5"
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

type domainPayload struct {
	Values []string `json:"values"`
}

var _ data_provider.DomainMatcherProvider = (*DomainSet)(nil)

type DomainSet struct {
	mu       sync.RWMutex
	mixM     *domain.MixMatcher[struct{}]
	mg       []domain.Matcher[struct{}]
	ruleFile string
	rules    []string
}

func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	ds := &DomainSet{
		mixM: domain.NewDomainMixMatcher(),
	}
	if len(cfg.Files) > 0 {
		ds.ruleFile = cfg.Files[0]
	}
	if err := LoadExpsAndFiles(cfg.Exps, cfg.Files, ds.mixM); err != nil {
		return nil, err
	}
	ds.rules = append(ds.rules, cfg.Exps...)
	for _, f := range cfg.Files {
		if strings.EqualFold(filepath.Ext(f), ".srs") {
			continue
		}
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			ds.rules = append(ds.rules, line)
		}
		file.Close()
	}
	if ds.mixM.Len() > 0 {
		ds.mg = append(ds.mg, ds.mixM)
	}
	for _, tag := range cfg.Sets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		ds.mg = append(ds.mg, provider.GetDomainMatcher())
	}
	bp.RegAPI(ds.api())
	return ds, nil
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return MatcherGroup(d.mg)
}

func (d *DomainSet) api() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/show", func(w http.ResponseWriter, r *http.Request) {
	    d.mu.RLock()
	    defer d.mu.RUnlock()
	    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	    for _, rule := range d.rules {
	        fmt.Fprintln(w, rule)
	    }
	})
	r.Get("/save", func(w http.ResponseWriter, r *http.Request) {
		d.mu.RLock()
		defer d.mu.RUnlock()
		if d.ruleFile == "" {
			http.Error(w, "no file configured", http.StatusInternalServerError)
			return
		}
		if err := writeRulesToFile(d.ruleFile, d.rules); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/add", func(w http.ResponseWriter, r *http.Request) {
		var p domainPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, pat := range p.Values {
			found := false
			for _, ex := range d.rules {
				if ex == pat {
					found = true
					break
				}
			}
			if !found {
				d.mixM.Add(pat, struct{}{})
				d.rules = append(d.rules, pat)
			}
		}
		if d.ruleFile != "" {
			writeRulesToFile(d.ruleFile, d.rules)
		}
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/del", func(w http.ResponseWriter, r *http.Request) {
		var p domainPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		newRules := make([]string, 0, len(d.rules))
		for _, ex := range d.rules {
			keep := true
			for _, bad := range p.Values {
				if ex == bad {
					keep = false
					break
				}
			}
			if keep {
				newRules = append(newRules, ex)
			}
		}
		d.rules = newRules
		newMix := domain.NewDomainMixMatcher()
		for _, pat := range d.rules {
			newMix.Add(pat, struct{}{})
		}
		d.mixM = newMix
		d.mg[0] = d.mixM
		if d.ruleFile != "" {
			writeRulesToFile(d.ruleFile, d.rules)
		}
		w.WriteHeader(http.StatusOK)
	})

	r.Post("/post", func(w http.ResponseWriter, r *http.Request) {
	    var p domainPayload
	    if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
	        http.Error(w, "invalid JSON", http.StatusBadRequest)
	        return
	    }

	    if d.ruleFile == "" || !strings.EqualFold(filepath.Ext(d.ruleFile), ".txt") {
	        http.Error(w, "no txt file configured, cannot post", http.StatusBadRequest)
	        return
	    }

	    tmpMix := domain.NewDomainMixMatcher()
	    tmpRules := make([]string, 0, len(p.Values))
	    for _, pat := range p.Values {
	        tmpMix.Add(pat, struct{}{})
	        tmpRules = append(tmpRules, pat)
	    }

	    d.mu.Lock()
	    d.mixM = tmpMix
	    if len(d.mg) > 0 {
	        d.mg[0] = d.mixM
	    } else {
	        d.mg = []domain.Matcher[struct{}]{d.mixM}
	    }
	    d.rules = tmpRules
	    d.mu.Unlock()

	    if err := writeRulesToFile(d.ruleFile, d.rules); err != nil {
	        http.Error(w, err.Error(), http.StatusInternalServerError)
	        return
	    }
	    w.WriteHeader(http.StatusOK)
	    fmt.Fprintf(w, "domain_set replaced with %d entries", len(d.rules))
	})

	return r
}

func writeRulesToFile(path string, rules []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, r := range rules {
		if _, err := f.WriteString(r + "\n"); err != nil {
			return err
		}
	}
	return nil
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
	var lastTxt string
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lastTxt = line
		m.Add(line, struct{}{})
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
		r.ReadByte()
		n, _ := binary.ReadUvarint(r)
		for i := uint64(0); i < n; i++ {
			ct += readRuleCompat(r, m, last)
		}
		r.ReadByte()
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
				m.Add(*last, struct{}{})
				count++
			}
			for _, d := range suffix {
				*last = "domain:" + d
				m.Add(*last, struct{}{})
				count++
			}
		case ruleItemDomainKeyword:
			sl, _ := varbin.ReadValue[[]string](r, binary.BigEndian)
			for _, d := range sl {
				*last = "keyword:" + d
				m.Add(*last, struct{}{})
				count++
			}
		case ruleItemDomainRegex:
			sl, _ := varbin.ReadValue[[]string](r, binary.BigEndian)
			for _, d := range sl {
				*last = "regexp:" + d
				m.Add(*last, struct{}{})
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
