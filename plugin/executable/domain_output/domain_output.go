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
	FilePath  string `yaml:"file_path"`
	MaxEntries int    `yaml:"max_entries"`
}

type domainOutput struct {
	filePath  string
	maxEntries int
	stats     map[string]int
	mu        sync.Mutex
}

func Init(_ *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	return &domainOutput{
		filePath:  cfg.FilePath,
		maxEntries: cfg.MaxEntries,
		stats:     make(map[string]int),
	}, nil
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	params := strings.Split(s, ",")
	if len(params) != 2 {
		return nil, errors.New("invalid quick setup arguments")
	}
	filePath := params[0]
	maxEntries, err := strconv.Atoi(params[1])
	if err != nil {
		return nil, err
	}
	return &domainOutput{
		filePath:  filePath,
		maxEntries: maxEntries,
		stats:     make(map[string]int),
	}, nil
}

func (d *domainOutput) Exec(ctx context.Context, qCtx *query_context.Context) error {
	for _, question := range qCtx.Q().Question {
		domain := question.Name
		d.mu.Lock()
		d.stats[domain]++
		d.mu.Unlock()
	}
	d.checkAndWrite()
	return nil
}

func (d *domainOutput) checkAndWrite() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.stats) < d.maxEntries {
		return
	}

	entries := make([][2]interface{}, 0, len(d.stats))
	for domain, count := range d.stats {
		entries = append(entries, [2]interface{}{count, domain})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i][0].(int) > entries[j][0].(int)
	})

	file, err := os.Create(d.filePath)
	if err != nil {
		return
	}
	defer file.Close()

	for i := 0; i < len(entries) && i < d.maxEntries; i++ {
		file.WriteString(fmt.Sprintf("%06d %s\n", entries[i][0], entries[i][1]))
	}
}
