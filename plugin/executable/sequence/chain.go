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

package sequence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"go.uber.org/zap"
)

// ADDED: A struct to hold a matcher and its name for logging.
type NamedMatcher struct {
	Name    string
	Matcher Matcher
}

type ChainNode struct {
	PluginName string
	// MODIFIED: Use the new struct to store matchers.
	Matches []NamedMatcher // Can be empty, indicates this node has no match specified.

	// At least one of E or RE must not nil.
	// In case both are set. E is preferred.
	E  Executable
	RE RecursiveExecutable
}

type ChainWalker struct {
	p        int
	chain    []*ChainNode
	jumpBack *ChainWalker
	logger   *zap.Logger
}

func NewChainWalker(chain []*ChainNode, jumpBack *ChainWalker, logger *zap.Logger) ChainWalker {
	return ChainWalker{
		chain:    chain,
		jumpBack: jumpBack,
		logger:   logger,
	}
}

func (w *ChainWalker) ExecNext(ctx context.Context, qCtx *query_context.Context) error {
	p := w.p
	// Evaluate rules' matchers in loop.
checkMatchesLoop:
	for p < len(w.chain) {
		n := w.chain[p]

		// MODIFIED: The loop now iterates over NamedMatcher.
		for _, namedMatch := range n.Matches {
			ok, err := namedMatch.Matcher.Match(ctx, qCtx)
			if err != nil {
				return err
			}

			// ADDED: Log matcher execution and result.
			if w.logger != nil {
				if ce := w.logger.Check(zap.DebugLevel, "dns query flows through matcher"); ce != nil {
					domain := "(no question)"
					if len(qCtx.Q().Question) > 0 {
						domain = strings.TrimSuffix(qCtx.Q().Question[0].Name, ".")
					}
					ce.Write(
						zap.String("trace_id", qCtx.TraceID),
						zap.String("domain", domain),
						zap.String("matcher_name", namedMatch.Name),
						zap.Bool("match_result", ok),
						zap.Time("time", time.Now()),
					)
				}
			}

			if ok {
				// Check if a domain_set name has already been stored.
				// This ensures we only capture the *first* one.
				if _, exists := qCtx.GetValue(query_context.KeyDomainSet); !exists {
					// START OF MODIFICATION
					// Priority 1: Check for switch6 match to identify BANAAAA.
					if strings.Contains(namedMatch.Name, "anonymous_match(switch6:") {
						if len(qCtx.Q().Question) > 0 && qCtx.Q().Question[0].Qtype == 28 { // 28 is dns.TypeAAAA
							qCtx.StoreValue(query_context.KeyDomainSet, "BANAAAA")
						}
					// Priority 2: Check for switch5 match to identify BANSOA, BANPTR, BANHTTPS.
					} else if strings.Contains(namedMatch.Name, "anonymous_match(switch5:") {
						if len(qCtx.Q().Question) > 0 {
							qtype := qCtx.Q().Question[0].Qtype
							var domainSetName string
							switch qtype {
							case 6: // dns.TypeSOA
								domainSetName = "BANSOA"
							case 12: // dns.TypePTR
								domainSetName = "BANPTR"
							case 65: // dns.TypeHTTPS
								domainSetName = "BANHTTPS"
							}
							if domainSetName != "" {
								qCtx.StoreValue(query_context.KeyDomainSet, domainSetName)
							}
						}
					// Priority 3: Original logic for qname match.
					} else {
						var ruleName string
						const suffix = ")"

						// Handle "qname: $rule" format
						const prefixWithDollar = "anonymous_match(qname: $"
						if strings.HasPrefix(namedMatch.Name, prefixWithDollar) {
							ruleName = strings.TrimPrefix(namedMatch.Name, prefixWithDollar)
							ruleName = strings.TrimSuffix(ruleName, suffix)
						} else {
							// Handle "qname: rule" format
							const prefixWithoutDollar = "anonymous_match(qname: "
							if strings.HasPrefix(namedMatch.Name, prefixWithoutDollar) {
								ruleName = strings.TrimPrefix(namedMatch.Name, prefixWithoutDollar)
								ruleName = strings.TrimSuffix(ruleName, suffix)
							}
						}

						if ruleName != "" {
							qCtx.StoreValue(query_context.KeyDomainSet, ruleName)
						}
					}
					// END OF MODIFICATION
				}
			} else {
				// Skip this node if a condition was not met.
				p++
				continue checkMatchesLoop
			}
		}

		if w.logger != nil {
			if ce := w.logger.Check(zap.DebugLevel, "dns query flows through plugin"); ce != nil {
				domain := "(no question)"
				if len(qCtx.Q().Question) > 0 {
					domain = strings.TrimSuffix(qCtx.Q().Question[0].Name, ".")
				}

				ce.Write(
					zap.String("trace_id", qCtx.TraceID),
					zap.Uint16("query_id", qCtx.Q().Id),
					zap.String("domain", domain),
					zap.String("plugin_name", n.PluginName),
					zap.Time("time", time.Now()),
				)
			}
		}

		// Exec rules' executables in loop, or in stack if it is a recursive executable.
		switch {
		case n.E != nil:
			if err := n.E.Exec(ctx, qCtx); err != nil {
				return err
			}
			p++
			continue
		case n.RE != nil:
			next := ChainWalker{
				p:        p + 1,
				chain:    w.chain,
				jumpBack: w.jumpBack,
				logger:   w.logger,
			}
			return n.RE.Exec(ctx, qCtx, next)
		default:
			panic("n cannot be executed")
		}
	}

	if w.jumpBack != nil { // End of chain, time to jump back.
		return w.jumpBack.ExecNext(ctx, qCtx)
	}

	// EoC.
	return nil
}

func (w *ChainWalker) nop() bool {
	return w.p >= len(w.chain)
}

func (s *Sequence) buildChain(bq BQ, rs []RuleConfig) error {
	c := make([]*ChainNode, 0, len(rs))
	for ri, r := range rs {
		n, err := s.newNode(bq, r, ri)
		if err != nil {
			return fmt.Errorf("failed to init rule #%d, %w", ri, err)
		}
		c = append(c, n)
	}
	s.chain = c
	return nil
}

func (s *Sequence) newNode(bq BQ, r RuleConfig, ri int) (*ChainNode, error) {
	n := new(ChainNode)

	// Populate PluginName for logging.
	if len(r.Tag) > 0 {
		n.PluginName = r.Tag
	} else if len(r.Type) > 0 {
		// FINAL MODIFICATION HERE: Include args in anonymous executable name.
		n.PluginName = fmt.Sprintf("anonymous_exec(%s: %v)", r.Type, r.Args)
	} else {
		n.PluginName = "unknown"
	}

	// init matches
	for mi, mc := range r.Matches {
		// MODIFIED: Use newMatcher that returns NamedMatcher.
		namedM, err := s.newMatcher(bq, mc, ri, mi)
		if err != nil {
			return nil, fmt.Errorf("failed to init matcher #%d, %w", mi, err)
		}
		n.Matches = append(n.Matches, namedM)
	}

	// init exec
	e, re, err := s.newExec(bq, r, ri)
	if err != nil {
		return nil, fmt.Errorf("failed to init exec, %w", err)
	}
	n.E = e
	n.RE = re
	return n, nil
}

// MODIFIED: This function now returns NamedMatcher.
func (s *Sequence) newMatcher(bq BQ, mc MatchConfig, ri, mi int) (NamedMatcher, error) {
	var m Matcher
	var name string

	switch {
	case len(mc.Tag) > 0:
		name = mc.Tag
		p, _ := bq.M().GetPlugin(name).(Matcher)
		if p == nil {
			return NamedMatcher{}, fmt.Errorf("can not find matcher %s", name)
		}
		if qc, ok := p.(QuickConfigurableMatch); ok {
			v, err := qc.QuickConfigureMatch(mc.Args)
			if err != nil {
				return NamedMatcher{}, fmt.Errorf("fail to configure plugin %s, %w", name, err)
			}
			m = v
		} else {
			m = p
		}

	case len(mc.Type) > 0:
		// FINAL MODIFICATION HERE: Include args in anonymous matcher name.
		name = fmt.Sprintf("anonymous_match(%s: %v)", mc.Type, mc.Args)
		f := GetMatchQuickSetup(mc.Type)
		if f == nil {
			return NamedMatcher{}, fmt.Errorf("invalid matcher type %s", mc.Type)
		}
		p, err := f(NewBQ(bq.M(), bq.L().Named(fmt.Sprintf("r%d.m%d", ri, mi))), mc.Args)
		if err != nil {
			return NamedMatcher{}, fmt.Errorf("failed to init matcher, %w", err)
		}
		s.anonymousPlugins = append(s.anonymousPlugins, p)
		m = p
	default:
		return NamedMatcher{}, errors.New("missing args")
	}

	if mc.Reverse {
		m = reverseMatcher(m)
		// Prepend "not(...)" to the name for clarity in logs.
		name = fmt.Sprintf("not(%s)", name)
	}
	return NamedMatcher{Name: name, Matcher: m}, nil
}

func (s *Sequence) newExec(bq BQ, rc RuleConfig, ri int) (Executable, RecursiveExecutable, error) {
	var exec any
	switch {
	case len(rc.Tag) > 0:
		p := bq.M().GetPlugin(rc.Tag)
		if p == nil {
			return nil, nil, fmt.Errorf("can not find executable %s", rc.Tag)
		}
		if qc, ok := p.(QuickConfigurableExec); ok {
			v, err := qc.QuickConfigureExec(rc.Args)
			if err != nil {
				return nil, nil, fmt.Errorf("fail to configure plugin %s, %w", rc.Tag, err)
			}
			exec = v
		} else {
			exec = p
		}
	case len(rc.Type) > 0:
		f := GetExecQuickSetup(rc.Type)
		if f == nil {
			return nil, nil, fmt.Errorf("invalid executable type %s", rc.Type)
		}
		v, err := f(NewBQ(bq.M(), bq.L().Named(fmt.Sprintf("r%d", ri))), rc.Args)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to init executable, %w", err)
		}
		s.anonymousPlugins = append(s.anonymousPlugins, v)
		exec = v
	default:
		return nil, nil, errors.New("missing args")
	}

	e, _ := exec.(Executable)
	re, _ := exec.(RecursiveExecutable)

	if re == nil && e == nil {
		return nil, nil, errors.New("invalid args, initialized object is not executable")
	}
	return e, re, nil
}

func closePlugin(p any) {
	if c, ok := p.(io.Closer); ok {
		_ = c.Close()
	}
}

func reverseMatcher(m Matcher) Matcher {
	return reverseMatch{m: m}
}

type reverseMatch struct {
	m Matcher
}

func (r reverseMatch) Match(ctx context.Context, qCtx *query_context.Context) (bool, error) {
	ok, err := r.m.Match(ctx, qCtx)
	if err != nil {
		return false, err
	}
	return !ok, nil
}
