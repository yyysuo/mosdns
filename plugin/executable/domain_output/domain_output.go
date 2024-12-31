/*
 * Copyright (C) 2024
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

package domain_output

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

const PluginType = "domain_output"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

type Args struct {
	FileStat   string `yaml:"file_stat"`
	FileRule   string `yaml:"file_rule"`
	MaxEntries int    `yaml:"max_entries"`
}

type domainOutput struct {
	fileStat   string
	fileRule   string
	maxEntries int
	stats      map[string]int
	mu         sync.Mutex
	totalCount int
}

func Init(_ *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	d := &domainOutput{
		fileStat:   cfg.FileStat,
		fileRule:   cfg.FileRule,
		maxEntries: cfg.MaxEntries,
		stats:      make(map[string]int),
	}
	// Load previous stats from the file when the plugin starts
	d.loadFromFile()
	return d, nil
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	params := strings.Split(s, ",")
	if len(params) != 3 {
		return nil, errors.New("invalid quick setup arguments")
	}
	fileStat := params[0]
	fileRule := params[1]
	maxEntries, err := strconv.Atoi(params[2])
	if err != nil {
		return nil, err
	}
	d := &domainOutput{
		fileStat:   fileStat,
		fileRule:   fileRule,
		maxEntries: maxEntries,
		stats:      make(map[string]int),
	}
	// Load previous stats from the file when the plugin starts
	d.loadFromFile()
	return d, nil
}

func (d *domainOutput) Exec(ctx context.Context, qCtx *query_context.Context) error {
	for _, question := range qCtx.Q().Question {
		domain := strings.TrimSuffix(question.Name, ".") // Remove the trailing dot from the domain
		d.mu.Lock()
		d.stats[domain]++
		d.totalCount++
		d.mu.Unlock()
	}

	// Trigger write if maxEntries is reached
	if d.totalCount >= d.maxEntries {
		d.checkAndWrite()
	}

	return nil
}

func (d *domainOutput) checkAndWrite() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Write to file when maxEntries are reached
	d.writeToFile()
	d.writeRuleFile()
}

func (d *domainOutput) loadFromFile() {
	// Load previous stats from fileStat
	file, err := os.Open(d.fileStat)
	if err != nil {
		// If file does not exist, no previous data
		return
	}
	defer file.Close()

	// Read lines and update stats map
	var domain string
	var count int
	for {
		_, err := fmt.Fscanf(file, "%d %s\n", &count, &domain)
		if err != nil {
			break
		}
		d.mu.Lock()
		d.stats[domain] = count
		d.mu.Unlock()
	}
}

func (d *domainOutput) writeToFile() {
	entries := make([][2]interface{}, 0, len(d.stats))
	for domain, count := range d.stats {
		entries = append(entries, [2]interface{}{count, domain})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i][0].(int) > entries[j][0].(int)
	})

	file, err := os.Create(d.fileStat)
	if err != nil {
		return
	}
	defer file.Close()

	for _, entry := range entries {
		// Format count to 10 digits
		file.WriteString(fmt.Sprintf("%010d %s\n", entry[0], entry[1]))
	}
}

func (d *domainOutput) writeRuleFile() {
	entries := make([][2]interface{}, 0, len(d.stats))
	for domain, count := range d.stats {
		entries = append(entries, [2]interface{}{count, domain})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i][0].(int) > entries[j][0].(int)
	})

	file, err := os.Create(d.fileRule)
	if err != nil {
		return
	}
	defer file.Close()

	for _, entry := range entries {
		file.WriteString(fmt.Sprintf("full:%s\n", entry[1]))
	}
}

// Shutdown hook to ensure writing unflushed stats
func (d *domainOutput) Shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Write any remaining stats if there are unflushed entries
	d.writeToFile()
	d.writeRuleFile()
}
