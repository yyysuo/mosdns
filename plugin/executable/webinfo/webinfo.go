package webinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	// FIX: Corrected the typo in the import path.
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/go-chi/chi/v5"
)

const (
	PluginType = "webinfo"
)

// 注册插件
func init() {
	coremain.RegNewPluginFunc(PluginType, newWebinfo, func() any { return new(Args) })
}

// Args 是插件的配置参数
type Args struct {
	File string `yaml:"file"`
}

// WebInfo 是插件的主结构体
type WebInfo struct {
	mu       sync.RWMutex
	filePath string
	// Replaced 'any' with 'interface{}' for backward compatibility.
	data interface{}
}

// newWebinfo 是插件的初始化函数
func newWebinfo(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	if cfg.File == "" {
		return nil, errors.New("webinfo: 'file' must be specified")
	}

	dir := filepath.Dir(cfg.File)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("webinfo: failed to create directory %s: %w", dir, err)
	}

	p := &WebInfo{
		filePath: cfg.File,
	}

	if err := p.loadData(); err != nil {
		return nil, fmt.Errorf("webinfo: failed to load initial data from %s: %w", p.filePath, err)
	}
	log.Printf("[webinfo] plugin instance created for file: %s", p.filePath)

	bp.RegAPI(p.api())

	return p, nil
}

// loadData 从文件加载 JSON 数据到内存
func (p *WebInfo) loadData() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	dataBytes, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[webinfo] file %s not found, initializing with empty data.", p.filePath)
			p.data = make(map[string]interface{})
			return nil
		}
		return err
	}

	if len(dataBytes) == 0 {
		p.data = make(map[string]interface{})
		return nil
	}

	var d interface{}
	if err := json.Unmarshal(dataBytes, &d); err != nil {
		return fmt.Errorf("failed to parse json from file %s: %w", p.filePath, err)
	}
	p.data = d

	return nil
}

// saveData 将内存中的数据保存到文件（原子写入）
func (p *WebInfo) saveData() error {
	dataBytes, err := json.MarshalIndent(p.data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data to json: %w", err)
	}

	tmpFile := p.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, dataBytes, 0644); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}
	if err := os.Rename(tmpFile, p.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to rename temporary file to final destination: %w", err)
	}

	return nil
}

// jsonError 是一个辅助函数
func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// api 定义并返回插件的 HTTP 接口
func (p *WebInfo) api() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		p.mu.RLock()
		defer p.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(p.data); err != nil {
			log.Printf("[webinfo] ERROR: failed to encode data to response: %v", err)
			jsonError(w, "Failed to encode response data", http.StatusInternalServerError)
		}
	})

	r.Put("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			jsonError(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}

		var newData interface{}
		if err := json.Unmarshal(body, &newData); err != nil {
			jsonError(w, "Invalid JSON format in request body", http.StatusBadRequest)
			return
		}

		p.mu.Lock()
		defer p.mu.Unlock()

		p.data = newData
		if err := p.saveData(); err != nil {
			log.Printf("[webinfo] ERROR: failed to save data to file %s: %v", p.filePath, err)
			jsonError(w, "Failed to save data to file", http.StatusInternalServerError)
			return
		}
		
		log.Printf("[webinfo] data updated successfully for file: %s", p.filePath)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(p.data)
	})

	return r
}
