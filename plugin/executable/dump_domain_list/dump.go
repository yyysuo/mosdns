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

package domain_list_to_file

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"strconv"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "domain_list_to_file"

func init() {
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

type Args struct {
	FilePath  string `yaml:"file_path"`  // File path for the domain list
	MaxEntries int    `yaml:"max_entries"` // Maximum number of entries before saving to file
}

type domainListToFilePlugin struct {
	args       *Args
	domainMap  map[string]int // Map for domain and access count
	mu         sync.Mutex
}

func newDomainListToFilePlugin(args *Args) (*domainListToFilePlugin, error) {
	return &domainListToFilePlugin{
		args:      args,
		domainMap: make(map[string]int),
	}, nil
}

func (p *domainListToFilePlugin) Exec(ctx context.Context, qCtx *query_context.Context) error {
	r := qCtx.R()
	if r != nil {
		if err := p.addDomain(r); err != nil {
			fmt.Printf("domain_list_to_file adddomain failed: %v\n", err)
		}
	}
	return nil
}

func (p *domainListToFilePlugin) addDomain(r *dns.Msg) error {
	for i := range r.Answer {
		switch rr := r.Answer[i].(type) {
		case *dns.A, *dns.AAAA:
			// Extract domain name
			domain := r.Question[0].Name

			// Increment access count for the domain
			p.mu.Lock()
			p.domainMap[domain]++
			p.mu.Unlock()

			// If we have reached the max entries for this filePath, save to file
			if len(p.domainMap) >= p.args.MaxEntries {
				if err := p.saveDomainsToFile(); err != nil {
					fmt.Printf("failed to save domains to file: %v\n", err)
				}
			}

		default:
			continue
		}
	}

	return nil
}

// Save domains to file (overwrite the file)
func (p *domainListToFilePlugin) saveDomainsToFile() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Convert the domain map to a slice of pairs
	var domainList []struct {
		Domain string
		Count  int
	}

	for domain, count := range p.domainMap {
		domainList = append(domainList, struct {
			Domain string
			Count  int
		}{domain, count})
	}

	// Sort by count in descending order
	sort.Slice(domainList, func(i, j int) bool {
		return domainList[i].Count > domainList[j].Count
	})

	// Open the file for writing (overwrite mode)
	file, err := os.OpenFile(p.args.FilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Write each domain with its count to the file
	for _, entry := range domainList {
		_, err := file.WriteString(fmt.Sprintf("full:%s %d\n", entry.Domain, entry.Count))
		if err != nil {
			return fmt.Errorf("failed to write domain to file: %w", err)
		}
	}

	// Not clearing the domainMap, it will continue accumulating
	return nil
}

func (p *domainListToFilePlugin) Close() error {
	// Save any remaining domains to the file when the plugin is closed
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.domainMap) > 0 {
		if err := p.saveDomainsToFile(); err != nil {
			fmt.Printf("failed to save domains on close: %v\n", err)
		}
	}
	return nil
}

// QuickSetup format: <file_path>,<max_entries>
// e.g. "/path/to/file1,100"
func QuickSetup(_ sequence.BQ, s string) (any, error) {
	fs := strings.Fields(s)
	if len(fs) != 2 {
		return nil, fmt.Errorf("expect 2 fields, got %d", len(fs))
	}

	args := new(Args)
	args.FilePath = fs[0]
	maxEntries, err := strconv.Atoi(fs[1])
	if err != nil {
		return nil, fmt.Errorf("invalid max_entries: %w", err)
	}
	args.MaxEntries = maxEntries

	return newDomainListToFilePlugin(args)
}
