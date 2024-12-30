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

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/plugin/executable"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	PluginType = "domain_output"
)

func init() {
	executable.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	FilePath   string `yaml:"file_path"`
	MaxEntries int    `yaml:"max_entries"`
}

func (a *Args) init() {
	utils.SetDefaultUnsignNum(&a.MaxEntries, 100)
}

// domainStats 用来保存域名和其请求次数
type domainStats struct {
	sync.Mutex
	stats map[string]int
}

func (d *domainStats) addDomain(domain string) {
	d.Lock()
	defer d.Unlock()
	d.stats[domain]++
}

func (d *domainStats) getStats() map[string]int {
	d.Lock()
	defer d.Unlock()
	// 返回当前统计的域名数据
	statsCopy := make(map[string]int)
	for k, v := range d.stats {
		statsCopy[k] = v
	}
	return statsCopy
}

type DomainOutputPlugin struct {
	args    *Args
	logger  *zap.Logger
	stats   *domainStats
	current int
}

func Init(bp *executable.BP, args any) (any, error) {
	plugin := &DomainOutputPlugin{
		args:    args.(*Args),
		logger:  bp.L(),
		stats:   &domainStats{stats: make(map[string]int)},
		current: 0,
	}

	return plugin, nil
}

func (d *DomainOutputPlugin) Exec(ctx query_context.Context, next executable.ChainWalker) error {
	// 获取请求的域名
	q := ctx.Q()
	if q == nil {
		return next.ExecNext(ctx)
	}

	domain := q.Question[0].Name
	// 统计域名请求
	d.stats.addDomain(domain)

	// 每达到 MaxEntries 条数据，写入文件
	d.current++
	if d.current >= d.args.MaxEntries {
		d.writeToFile()
		d.current = 0
	}

	return next.ExecNext(ctx)
}

func (d *DomainOutputPlugin) writeToFile() {
	file, err := os.OpenFile(d.args.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		d.logger.Error("failed to open file", zap.String("file", d.args.FilePath), zap.Error(err))
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for domain, count := range d.stats.getStats() {
		_, err := fmt.Fprintf(writer, "%s %d\n", domain, count)
		if err != nil {
			d.logger.Error("failed to write to file", zap.String("file", d.args.FilePath), zap.Error(err))
			return
		}
	}

	err = writer.Flush()
	if err != nil {
		d.logger.Error("failed to flush writer", zap.String("file", d.args.FilePath), zap.Error(err))
	}
	d.stats = &domainStats{stats: make(map[string]int)} // 清空统计数据
}

func (d *DomainOutputPlugin) Close() error {
	// 插件关闭时写入剩余的统计数据
	d.writeToFile()
	return nil
}

