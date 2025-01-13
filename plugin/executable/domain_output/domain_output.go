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
	"time"

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
	FileStat     string `yaml:"file_stat"`
	FileRule     string `yaml:"file_rule"`
	MaxEntries   int    `yaml:"max_entries"`
	DumpInterval int    `yaml:"dump_interval"`
}

type domainOutput struct {
	fileStat     string
	fileRule     string
	maxEntries   int
	dumpInterval time.Duration
	stats        map[string]int
	mu           sync.Mutex
	totalCount   int
	entryCounter int // 独立计数器，用于统计当前已处理的请求数
	stopChan     chan struct{}
}

func Init(_ *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	if cfg.DumpInterval <= 0 {
		cfg.DumpInterval = 60 // 默认值为60秒
	}
	d := &domainOutput{
		fileStat:     cfg.FileStat,
		fileRule:     cfg.FileRule,
		maxEntries:   cfg.MaxEntries,
		dumpInterval: time.Duration(cfg.DumpInterval) * time.Second,
		stats:        make(map[string]int),
		stopChan:     make(chan struct{}),
	}
	d.loadFromFile()

	// 启动定时写入协程
	go d.startDumpTicker()

	return d, nil
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	params := strings.Split(s, ",")
	if len(params) != 4 {
		return nil, errors.New("invalid quick setup arguments")
	}
	fileStat := params[0]
	fileRule := params[1]
	maxEntries, err := strconv.Atoi(params[2])
	if err != nil {
		return nil, err
	}
	dumpInterval, err := strconv.Atoi(params[3])
	if err != nil || dumpInterval <= 0 {
		dumpInterval = 60 // 默认值为60秒
	}
	d := &domainOutput{
		fileStat:     fileStat,
		fileRule:     fileRule,
		maxEntries:   maxEntries,
		dumpInterval: time.Duration(dumpInterval) * time.Second,
		stats:        make(map[string]int),
		stopChan:     make(chan struct{}),
	}
	d.loadFromFile()

	// 启动定时写入协程
	go d.startDumpTicker()

	return d, nil
}

func (d *domainOutput) Exec(ctx context.Context, qCtx *query_context.Context) error {
	for _, question := range qCtx.Q().Question {
		domain := strings.TrimSuffix(question.Name, ".") // Remove the trailing dot from the domain
		d.mu.Lock()
		d.stats[domain]++
		d.totalCount++
		d.entryCounter++
		d.mu.Unlock()
	}

	// 如果达到maxEntries计数，则立即触发写入并清空计数器
	if d.entryCounter >= d.maxEntries {
		d.checkAndWrite()
	}

	return nil
}

func (d *domainOutput) checkAndWrite() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writeAll()
	d.entryCounter = 0 // 清空计数器，等待下一轮触发
}

func (d *domainOutput) loadFromFile() {
	file, err := os.Open(d.fileStat)
	if err != nil {
		return
	}
	defer file.Close()

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

func (d *domainOutput) startDumpTicker() {
	ticker := time.NewTicker(d.dumpInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.checkAndWrite()
		case <-d.stopChan:
			return
		}
	}
}

func (d *domainOutput) Shutdown() {
	close(d.stopChan)

	d.mu.Lock()
	defer d.mu.Unlock()

	d.writeAll() // 写入所有数据
}

func (d *domainOutput) writeAll() {
	d.writeToFile()
	d.writeRuleFile()
}

