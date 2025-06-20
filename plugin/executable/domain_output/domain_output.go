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
	"bytes"                          // 新增
	"context"
	"encoding/json"                  // 新增
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"                           // 新增
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
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
	FileStat       string `yaml:"file_stat"`
	FileRule       string `yaml:"file_rule"`
	GenRule        string `yaml:"gen_rule"`        // 生成规则文件的路径
	Pattern        string `yaml:"pattern"`         // 规则模板，模板中的 "DOMAIN" 替换为域名
	AppendedString string `yaml:"appended_string"` // 如果配置了此项，则在生成的文件第一行添加此字符串
	MaxEntries     int    `yaml:"max_entries"`
	DumpInterval   int    `yaml:"dump_interval"`
	DomainSetURL   string `yaml:"domain_set_url"`  // 新增：可选，domain_set 插件 /post 接口 URL，用于热更新
}

type domainOutput struct {
	fileStat       string
	fileRule       string
	genRule        string // 生成规则文件路径
	pattern        string // 规则模板
	appendedString string // 附加字符串，写入生成规则文件的第一行
	maxEntries     int
	dumpInterval   time.Duration
	stats          map[string]int
	mu             sync.Mutex
	totalCount     int
	entryCounter   int // 用于判断写入的计数器
	stopChan       chan struct{}
	domainSetURL   string // 新增：热更新 endpoint
}

func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	if cfg.DumpInterval <= 0 {
		cfg.DumpInterval = 60 // 默认值为60秒
	}
	d := &domainOutput{
		fileStat:       cfg.FileStat,
		fileRule:       cfg.FileRule,
		genRule:        cfg.GenRule,
		pattern:        cfg.Pattern,
		appendedString: cfg.AppendedString,
		maxEntries:     cfg.MaxEntries,
		dumpInterval:   time.Duration(cfg.DumpInterval) * time.Second,
		stats:          make(map[string]int),
		stopChan:       make(chan struct{}),
		domainSetURL:   cfg.DomainSetURL, // 保存新字段
	}
	d.loadFromFile()

	// 启动定时写入协程
	go d.startDumpTicker()
	// 注册 /plugins/<tag>/flush，刷新并重写所有文件
	bp.RegAPI(d.Api())

	return d, nil
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	params := strings.Split(s, ",")
	if len(params) < 6 || len(params) > 7 {
		return nil, errors.New("invalid quick setup arguments: need 6 or 7 fields")
	}
	fileStat := params[0]
	fileRule := params[1]
	genRule := params[2]
	pattern := params[3]
	maxEntries, err := strconv.Atoi(params[4])
	if err != nil {
		return nil, err
	}
	dumpInterval, err := strconv.Atoi(params[5])
	if err != nil || dumpInterval <= 0 {
		dumpInterval = 60
	}
	// QuickSetup 中未支持 appended_string，可按需要扩展（比如第7个参数）
	d := &domainOutput{
		fileStat:     fileStat,
		fileRule:     fileRule,
		genRule:      genRule,
		pattern:      pattern,
		maxEntries:   maxEntries,
		dumpInterval: time.Duration(dumpInterval) * time.Second,
		stats:        make(map[string]int),
		stopChan:     make(chan struct{}),
	}
	if len(params) == 7 {
		d.domainSetURL = params[6] // 支持第7个可选参数
	}
	d.loadFromFile()

	// 启动定时写入协程
	go d.startDumpTicker()

	return d, nil
}

func (d *domainOutput) Exec(ctx context.Context, qCtx *query_context.Context) error {
	for _, question := range qCtx.Q().Question {
		domain := strings.TrimSuffix(question.Name, ".") // 去掉末尾的点
		d.mu.Lock()
		d.stats[domain]++
		d.totalCount++
		d.entryCounter++
		d.mu.Unlock()
	}

	// 达到 maxEntries 时立即写入并清空 entryCounter（但统计数据不清空）
	if d.entryCounter >= d.maxEntries {
		d.checkAndWrite()
	}

	return nil
}

func (d *domainOutput) checkAndWrite() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writeAll()
	d.entryCounter = 0 // 清空写入计数器
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
	entries := d.getSortedEntries()

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
	entries := d.getSortedEntries()

	file, err := os.Create(d.fileRule)
	if err != nil {
		return
	}
	defer file.Close()

	for _, entry := range entries {
		file.WriteString(fmt.Sprintf("full:%s\n", entry[1]))
	}
}

// 新增：生成规则文件，将 pattern 中的 "DOMAIN" 替换为每个域名。
// 如果配置了 appendedString，则在文件第一行写入该字符串。
func (d *domainOutput) writeGenRuleFile() {
	if d.genRule == "" || d.pattern == "" {
		return
	}

	entries := make([]string, 0, len(d.stats))
	// 遍历所有域名
	for domain := range d.stats {
		line := strings.ReplaceAll(d.pattern, "DOMAIN", domain)
		entries = append(entries, line)
	}
	// 按字母顺序排序
	sort.Strings(entries)

	file, err := os.Create(d.genRule)
	if err != nil {
		return
	}
	defer file.Close()

	// 如果配置了 appendedString，则写入到第一行
	if d.appendedString != "" {
		file.WriteString(d.appendedString + "\n")
	}

	for _, line := range entries {
		file.WriteString(line + "\n")
	}
}

// getSortedEntries 返回一个按统计值降序排序的切片，每个元素为 [count, domain]
func (d *domainOutput) getSortedEntries() [][2]interface{} {
	entries := make([][2]interface{}, 0, len(d.stats))
	for domain, count := range d.stats {
		entries = append(entries, [2]interface{}{count, domain})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i][0].(int) > entries[j][0].(int)
	})
	return entries
}

// writeAll 同时写入统计、规则和生成规则文件，并触发热更新
func (d *domainOutput) writeAll() {
	d.writeToFile()
	d.writeRuleFile()
	d.writeGenRuleFile()
	d.pushToDomainSet() // 新增：全量 POST 到 domain_set
}

// pushToDomainSet 异步 POST 全量 "full:domain" 列表到 domain_set /post
func (d *domainOutput) pushToDomainSet() {
	if d.domainSetURL == "" {
		return
	}

	vals := make([]string, 0, len(d.stats))
	for domain := range d.stats {
		vals = append(vals, fmt.Sprintf("full:%s", domain))
	}
	sort.Strings(vals)

	payload := struct{ Values []string `json:"values"` }{Values: vals}
	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[domain_output] marshal payload error: %v\n", err)
		return
	}

	go func() {
		req, err := http.NewRequest("POST", d.domainSetURL, bytes.NewReader(body))
		if err != nil {
			fmt.Printf("[domain_output] create POST request error: %v\n", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Printf("[domain_output] POST to domain_set error: %v\n", err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Printf("[domain_output] pushed %d rules to domain_set, status=%s\n", len(vals), resp.Status)
	}()
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
	d.writeAll() // 关闭时无条件写入所有数据
}

// restartSelf 用 syscall.Exec 重启当前二进制
func restartSelf() {
	// 微小延迟，确保 HTTP 响应已发送
	time.Sleep(100 * time.Millisecond)

	bin, err := os.Executable()
	if err != nil {
		// 无法获取可执行文件路径时直接退出，
		// 让外部如 systemd/容器重启它
		os.Exit(0)
	}
	args := os.Args
	env := os.Environ()
	syscall.Exec(bin, args, env)
}

// Api 返回 domain_output 插件的路由，包含 /flush
func (d *domainOutput) Api() *chi.Mux {
	r := chi.NewRouter()

	// GET /plugins/{your_plugin_tag}/flush
	r.Get("/flush", func(w http.ResponseWriter, req *http.Request) {
		// 1. 清空内存统计
		d.mu.Lock()
		d.stats = make(map[string]int)
		d.totalCount = 0
		d.entryCounter = 0
		// 2. 立即写入所有三个文件：stat、rule、gen_rule
		d.writeAll()
		d.mu.Unlock()

		// 3. 返回确认
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("domain_output flushed and files rewritten; restarting…"))
	})

	// save 路由：不清空，立即写文件
	r.Get("/save", func(w http.ResponseWriter, req *http.Request) {
		d.mu.Lock()
		d.writeAll()
		d.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("domain_output files saved; restarting…"))
	})

	// GET /plugins/{tag}/show
	// 将 file_stat 文件内容以纯文本输出到浏览器
	r.Get("/show", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		f, err := os.Open(d.fileStat)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to open stat file: %v", err), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, fmt.Sprintf("failed to send stat file content: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// GET /plugins/{tag}/restartall
	// 仅执行重启逻辑（调用 restartSelf）
	r.Get("/restartall", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mosdns restarted"))
		go restartSelf()
	})

	return r
}
