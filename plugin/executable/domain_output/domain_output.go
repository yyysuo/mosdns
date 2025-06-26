package domain_output

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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
	GenRule        string `yaml:"gen_rule"`
	Pattern        string `yaml:"pattern"`
	AppendedString string `yaml:"appended_string"`
	MaxEntries     int    `yaml:"max_entries"`
	DumpInterval   int    `yaml:"dump_interval"`
	DomainSetURL   string `yaml:"domain_set_url"`
}

type domainOutput struct {
	fileStat       string
	fileRule       string
	genRule        string
	pattern        string
	appendedString string
	maxEntries     int
	dumpInterval   time.Duration

	stats        map[string]int // 存储统计数据，受 mu 保护
	mu           sync.Mutex     // 保护 stats, totalCount, entryCounter 的并发访问
	totalCount   int            // 总计数，受 mu 保护
	entryCounter int            // 自上次写入或启动以来，处理的域名数量，受 mu 保护

	writeSignalChan chan struct{} // 用于通知 worker goroutine 执行写入操作的通道
	stopChan        chan struct{} // 用于通知 worker goroutine 停止的通道
	workerDoneChan  chan struct{} // 用于等待 worker goroutine 完成的通道

	domainSetURL string
}

// 定义写入模式
type WriteMode int

const (
	WriteModePeriodic WriteMode = iota // 周期性写入或达到阈值写入，无数据则不写
	WriteModeFlush                     // /flush API 触发，清空内存并写入空文件
	WriteModeSave                      // /save API 触发 或 优雅关闭时触发，写入当前内存状态，无论是否为空
)

func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	if cfg.DumpInterval <= 0 {
		cfg.DumpInterval = 60 // 默认值为60秒
	}
	d := &domainOutput{
		fileStat:        cfg.FileStat,
		fileRule:        cfg.FileRule,
		genRule:         cfg.GenRule,
		pattern:         cfg.Pattern,
		appendedString:  cfg.AppendedString,
		maxEntries:      cfg.MaxEntries,
		dumpInterval:    time.Duration(cfg.DumpInterval) * time.Second,
		stats:           make(map[string]int),
		writeSignalChan: make(chan struct{}, 1), // 缓冲1，避免Exec阻塞
		stopChan:        make(chan struct{}),
		workerDoneChan:  make(chan struct{}),
		domainSetURL:    cfg.DomainSetURL,
	}
	d.loadFromFile() // 首次加载文件仍然在主 goroutine

	// 启动异步工作者协程
	go d.startWorker()
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
	// QuickSetup 中未支持 appended_string，可按需要扩展
	d := &domainOutput{
		fileStat:        fileStat,
		fileRule:        fileRule,
		genRule:         genRule,
		pattern:         pattern,
		maxEntries:      maxEntries,
		dumpInterval:    time.Duration(dumpInterval) * time.Second,
		stats:           make(map[string]int),
		writeSignalChan: make(chan struct{}, 1), // 缓冲1，避免Exec阻塞
		stopChan:        make(chan struct{}),
		workerDoneChan:  make(chan struct{}),
	}
	if len(params) == 7 {
		d.domainSetURL = params[6]
	}
	d.loadFromFile()

	// 启动异步工作者协程
	go d.startWorker()

	return d, nil
}

// Exec 方法现在只负责更新内存统计和非阻塞地发送写入信号
func (d *domainOutput) Exec(ctx context.Context, qCtx *query_context.Context) error {
	d.mu.Lock() // 快速获取锁，更新内存统计
	for _, question := range qCtx.Q().Question {
		domain := strings.TrimSuffix(question.Name, ".") // 去掉末尾的点
		d.stats[domain]++
		d.totalCount++
		d.entryCounter++
	}
	// 检查是否达到阈值，如果达到，尝试发送写入信号
	// select-default 模式确保发送是无阻塞的，如果通道已满，则跳过发送
	if d.entryCounter >= d.maxEntries {
		select {
		case d.writeSignalChan <- struct{}{}:
			// 信号发送成功
		default:
			// 通道已满，说明写入操作已经在队列中或正在进行，无需重复发送信号
			// 这避免了 Exec 方法因为通道阻塞而等待
		}
	}
	d.mu.Unlock() // 快速释放锁

	return nil // Exec 立即返回，不等待文件写入
}

// startWorker 是异步工作者 goroutine
func (d *domainOutput) startWorker() {
	ticker := time.NewTicker(d.dumpInterval)
	defer ticker.Stop()
	defer close(d.workerDoneChan) // 工作者退出时关闭此通道

	for {
		select {
		case <-ticker.C:
			// 定时触发写入
			d.performWrite(WriteModePeriodic)
		case <-d.writeSignalChan:
			// 由 Exec 触发的写入信号
			d.performWrite(WriteModePeriodic)
		case <-d.stopChan:
			// 收到停止信号，worker 退出，将最终写入的任务留给 Shutdown 方法
			fmt.Println("[domain_output] worker received stop signal, stopping.")
			return
		}
	}
}

// performWrite 是实际执行文件写入的函数
// mode 参数指示写入的模式 (周期性、清空、保存)
func (d *domainOutput) performWrite(mode WriteMode) {
	d.mu.Lock()

	var statsToDump map[string]int

	switch mode {
	case WriteModePeriodic:
		// 复制 stats 映射
		statsToDump = make(map[string]int, len(d.stats))
		for k, v := range d.stats {
			statsToDump[k] = v
		}
		// 如果周期性写入且没有数据，则不执行写入操作
		if len(statsToDump) == 0 {
			d.mu.Unlock()
			return
		}
		d.entryCounter = 0 // 重置计数器
	case WriteModeFlush:
		// 复制 stats 映射 (将是空的，因为目标是清空文件)
		statsToDump = make(map[string]int) // 直接创建空map
		// 清空内存中的统计数据
		d.stats = make(map[string]int)
		d.totalCount = 0
		d.entryCounter = 0 // 重置计数器
	case WriteModeSave:
		// 复制 stats 映射
		statsToDump = make(map[string]int, len(d.stats))
		for k, v := range d.stats {
			statsToDump[k] = v
		}
		d.entryCounter = 0 // 重置计数器
	}

	d.mu.Unlock() // 立即释放锁

	// 执行文件写入操作
	d.doWriteFiles(statsToDump)

	// 触发热更新
	// 只有当有数据时，或在 Flush/Save 模式下 (即使数据为空也要通知更新状态)
	if len(statsToDump) > 0 || mode == WriteModeFlush || mode == WriteModeSave {
		d.pushToDomainSet(statsToDump)
	}
}

// doWriteFiles 封装了实际的文件写入逻辑
// 不再进行排序，直接遍历 map 写入
func (d *domainOutput) doWriteFiles(statsData map[string]int) {
	// Helper function to write to a file
	// filePath: 要写入的文件路径
	// writeContent: 一个函数，接收io.Writer，返回写入错误。用于定义具体写入内容。
	writeFile := func(filePath string, writeContent func(io.Writer) error) {
		if filePath == "" { // 如果文件路径未配置，则跳过
			return
		}
		file, err := os.Create(filePath) // os.Create 会清空文件或创建文件
		if err != nil {
			fmt.Printf("[domain_output] failed to create file %s: %v\n", filePath, err)
			return // 创建文件失败，直接返回，不尝试写入
		}
		defer file.Close() // 确保文件句柄被关闭

		if err := writeContent(file); err != nil {
			fmt.Printf("[domain_output] failed to write to file %s: %v\n", filePath, err)
		}
	}

	// 写入 stat 文件
	writeFile(d.fileStat, func(w io.Writer) error {
		for domain, count := range statsData {
			if _, err := w.Write([]byte(fmt.Sprintf("%010d %s\n", count, domain) + "\n")); err != nil {
				return err
			}
		}
		return nil
	})

	// 写入 rule 文件
	writeFile(d.fileRule, func(w io.Writer) error {
		for domain := range statsData {
			if _, err := w.Write([]byte(fmt.Sprintf("full:%s\n", domain) + "\n")); err != nil {
				return err
			}
		}
		return nil
	})

	// 写入 genRule 文件
	writeFile(d.genRule, func(w io.Writer) error {
		if d.pattern == "" { // 如果没有pattern，不生成genRule文件内容
			return nil
		}
		if d.appendedString != "" {
			if _, err := w.Write([]byte(d.appendedString + "\n")); err != nil {
				return err
			}
		}
		for domain := range statsData {
			line := strings.ReplaceAll(d.pattern, "DOMAIN", domain)
			if _, err := w.Write([]byte(line + "\n")); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *domainOutput) loadFromFile() {
	file, err := os.Open(d.fileStat)
	if err != nil {
		if !os.IsNotExist(err) { // 只有不是文件不存在的错误才打印
			fmt.Printf("[domain_output] failed to open stat file %s: %v\n", d.fileStat, err)
		}
		return
	}
	defer file.Close()

	d.mu.Lock() // 加载时也需要保护 stats
	defer d.mu.Unlock()

	var domain string
	var count int
	for {
		_, err := fmt.Fscanf(file, "%d %s\n", &count, &domain)
		if err != nil {
			break
		}
		d.stats[domain] = count
		d.totalCount += count
	}
	fmt.Printf("[domain_output] loaded %d entries from %s\n", len(d.stats), d.fileStat)
}

// pushToDomainSet 异步 POST 全量 "full:domain" 列表到 domain_set /post
// 使用传入的 statsData 而不是 d.stats，且不再进行排序
func (d *domainOutput) pushToDomainSet(statsData map[string]int) {
	if d.domainSetURL == "" {
		return
	}

	vals := make([]string, 0, len(statsData))
	for domain := range statsData { // 直接遍历map，不排序
		vals = append(vals, fmt.Sprintf("full:%s", domain))
	}

	payload := struct{ Values []string `json:"values"` }{Values: vals}
	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[domain_output] marshal payload error: %v\n", err)
		return
	}

	go func() { // 独立协程执行 HTTP 请求
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

// Shutdown 方法实现了 io.Closer 接口，用于优雅关闭时保存数据
func (d *domainOutput) Shutdown() error { // <-- 关键修改：添加 `error` 返回值
	fmt.Println("[domain_output] initiating shutdown...")
	close(d.stopChan)      // 通知 worker 停止
	<-d.workerDoneChan // 等待 worker goroutine 退出

	// 在 worker 退出后，执行一次最终的保存操作
	// 这将确保在 MosDNS 优雅关闭时，所有内存中的数据都被保存到磁盘
	d.performWrite(WriteModeSave)

	fmt.Println("[domain_output] shutdown complete.")
	return nil // <-- 关键修改：返回 nil
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

// Api 返回 domain_output 插件的路由
func (d *domainOutput) Api() *chi.Mux {
	r := chi.NewRouter()

	// GET /plugins/{your_plugin_tag}/flush
	// 清空内存统计并触发一次写入 (文件会被清空)
	r.Get("/flush", func(w http.ResponseWriter, req *http.Request) {
		// API 调用仍然是同步的，以便调用者知道操作是否完成
		d.performWrite(WriteModeFlush)

		w.WriteHeader(http.StatusOK)
		// Removed: go restartSelf()
		w.Write([]byte("domain_output flushed and files rewritten."))
	})

	// save 路由：不清空，立即写文件 (文件将反映当前内存状态，即使为空)
	r.Get("/save", func(w http.ResponseWriter, req *http.Request) {
		// API 调用仍然是同步的
		d.performWrite(WriteModeSave)

		w.WriteHeader(http.StatusOK)
		// Removed: go restartSelf()
		w.Write([]byte("domain_output files saved."))
	})

	// GET /plugins/{tag}/show
	// 将 file_stat 文件内容以纯文本输出到浏览器
	r.Get("/show", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		// 直接读取文件内容，不涉及插件内部状态的修改
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
		// 在重启前，显式地保存当前内存中的数据，确保不丢失
		d.performWrite(WriteModeSave) // 确保在重启前，将内存中的数据保存到磁盘

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mosdns restarted"))
		go restartSelf()
	})

	return r
}
