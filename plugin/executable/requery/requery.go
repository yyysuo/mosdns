package requery

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"github.com/robfig/cron/v3"
)

const (
	PluginType = "requery"
)

// ----------------------------------------------------------------------------
// 1. Plugin Registration and Initialization
// ----------------------------------------------------------------------------

func init() {
	coremain.RegNewPluginFunc(PluginType, newRequery, func() any { return new(Args) })
}

// Args is the plugin's configuration arguments from the main YAML config.
type Args struct {
	File string `yaml:"file"` // Path to the requeryconfig.json file
}

// newRequery is the plugin's initialization function.
func newRequery(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)
	if cfg.File == "" {
		return nil, errors.New("requery: 'file' for config json must be specified")
	}

	dir := filepath.Dir(cfg.File)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("requery: failed to create directory %s: %w", dir, err)
	}

	p := &Requery{
		filePath:   cfg.File,
		scheduler:  cron.New(),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	if err := p.loadConfig(); err != nil {
		return nil, fmt.Errorf("requery: failed to load initial config from %s: %w", p.filePath, err)
	}

	// Resiliency check: If mosdns was stopped while a task was running, mark it as failed.
	p.mu.Lock()
	if p.config.Status.TaskState == "running" {
		log.Println("[requery] WARN: Found task in 'running' state on startup. Marking as 'failed'.")
		p.config.Status.TaskState = "failed"
		p.config.Status.LastRunEndTime = time.Now().UTC()
		_ = p.saveConfigUnlocked() // Attempt to save the updated state
	}
	p.mu.Unlock()


	// Start the scheduler's goroutine once. It will run forever.
	p.scheduler.Start()
	log.Println("[requery] Scheduler started.")
	
	// Now, add the initial job based on the loaded config.
	if err := p.setupScheduler(); err != nil {
		log.Printf("[requery] WARN: Failed to setup initial scheduler job, it will be disabled: %v", err)
	}
	
	bp.RegAPI(p.api())
	
	log.Printf("[requery] plugin instance created for config file: %s", p.filePath)
	return p, nil
}

// ----------------------------------------------------------------------------
// 2. Main Plugin Struct and Configuration Structs
// ----------------------------------------------------------------------------

// Requery is the main struct for the plugin.
type Requery struct {
	mu         sync.RWMutex
	filePath   string
	config     *Config
	scheduler  *cron.Cron
	taskCtx    context.Context
	taskCancel context.CancelFunc
	httpClient *http.Client
}

// Config maps directly to the requeryconfig.json file structure.
type Config struct {
	DomainProcessing  DomainProcessing   `json:"domain_processing"`
	URLActions        URLActions         `json:"url_actions"`
	Scheduler         SchedulerConfig    `json:"scheduler"`
	ExecutionSettings ExecutionSettings  `json:"execution_settings"`
	Status            Status             `json:"status"`
}

type DomainProcessing struct {
	SourceFiles []SourceFile `json:"source_files"`
	OutputFile  string       `json:"output_file"`
}

type SourceFile struct {
	Alias string `json:"alias"`
	Path  string `json:"path"`
}

type URLActions struct {
	SaveRules  []string `json:"save_rules"`
	FlushRules []string `json:"flush_rules"`
}

type SchedulerConfig struct {
	Enabled         bool   `json:"enabled"`
	StartDatetime   string `json:"start_datetime"` // ISO 8601 format
	IntervalMinutes int    `json:"interval_minutes"`
}

type ExecutionSettings struct {
	QueriesPerSecond int    `json:"queries_per_second"`
	ResolverAddress  string `json:"resolver_address"`
	URLCallDelayMS   int    `json:"url_call_delay_ms"`
}

type Status struct {
	TaskState           string    `json:"task_state"` // "idle", "running", "failed", "cancelled"
	LastRunStartTime    time.Time `json:"last_run_start_time,omitempty"`
	LastRunEndTime      time.Time `json:"last_run_end_time,omitempty"`
	LastRunDomainCount  int       `json:"last_run_domain_count"`
	Progress            Progress  `json:"progress"`
}

type Progress struct {
	Processed int64 `json:"processed"`
	Total     int64 `json:"total"`
}


// ----------------------------------------------------------------------------
// 3. Core Task Workflow
// ----------------------------------------------------------------------------

// runTask executes the entire requery workflow. It's designed to be run in a goroutine.
func (p *Requery) runTask(ctx context.Context) {
	p.mu.Lock()
	if p.config.Status.TaskState == "running" {
		log.Println("[requery] Task trigger ignored: a task is already running.")
		p.mu.Unlock()
		return
	}
	
	p.config.Status.TaskState = "running"
	p.config.Status.LastRunStartTime = time.Now().UTC()
	p.config.Status.LastRunEndTime = time.Time{} // Clear end time
	p.config.Status.Progress.Processed = 0
	p.config.Status.Progress.Total = 0
	_ = p.saveConfigUnlocked()
	p.mu.Unlock()

	// Defer block to ensure state is cleaned up on any exit path (success, failure, cancellation).
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()

		if p.config.Status.TaskState == "running" {
			p.config.Status.TaskState = "idle" // Assume success unless overridden
		}

		if r := recover(); r != nil {
			log.Printf("[requery] FATAL: Task panicked: %v", r)
			p.config.Status.TaskState = "failed"
		}
		
		p.config.Status.LastRunEndTime = time.Now().UTC()
		_ = p.saveConfigUnlocked()

		p.taskCancel = nil
	} ()

	log.Println("[requery] Starting a new task.")

	// Step 1: Save current rules
	log.Println("[requery] Step 1: Saving rules...")
	if err := p.callURLs(ctx, p.config.URLActions.SaveRules); err != nil {
		p.setFailedState("failed during save_rules step: %v", err)
		return
	}

	// Step 2 & 3: Consolidate domains and write backup
	log.Println("[requery] Step 2 & 3: Merging domains and creating backup...")
	domains, err := p.mergeAndBackupDomains(ctx)
	if err != nil {
		p.setFailedState("failed during domain merge and backup: %v", err)
		return
	}
	if len(domains) == 0 {
		log.Println("[requery] No domains found to process. Task finished.")
		return
	}
	
	// Step 4: Flush old rules
	log.Println("[requery] Step 4: Flushing old rules...")
	if err := p.callURLs(ctx, p.config.URLActions.FlushRules); err != nil {
		p.setFailedState("failed during flush_rules step: %v", err)
		return
	}

	// Update status with total domain count
	p.mu.Lock()
	p.config.Status.LastRunDomainCount = len(domains)
	p.config.Status.Progress.Total = int64(len(domains))
	p.mu.Unlock()

	// Step 6: Re-query domains
	log.Printf("[requery] Step 6: Re-querying %d domains...", len(domains))
	err = p.resendDNSQueries(ctx, domains)
	if err != nil {
		// The error (e.g., cancellation) is handled inside resendDNSQueries by setting the state.
		log.Printf("[requery] Task stopped during DNS query phase: %v", err)
		return
	}

	// Step 7 (Final): Save rules again after requery
	log.Println("[requery] Step 7: Performing final save of rules...")
	if err := p.callURLs(ctx, p.config.URLActions.SaveRules); err != nil {
		p.setFailedState("failed during final save_rules step: %v", err)
		return
	}

	log.Println("[requery] Task completed successfully.")
}

// mergeAndBackupDomains handles steps 2 and 3 of the workflow with accumulator logic.
func (p *Requery) mergeAndBackupDomains(ctx context.Context) ([]string, error) {
	existingDomains, err := p.readDomainsFromFile(p.config.DomainProcessing.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read existing backup file %s: %w", p.config.DomainProcessing.OutputFile, err)
	}
	domainSet := make(map[string]struct{}, len(existingDomains))
	for _, domain := range existingDomains {
		domainSet[domain] = struct{}{}
	}
	log.Printf("[requery] Loaded %d unique domains from existing backup file.", len(domainSet))

	domainPattern := regexp.MustCompile(`^full:(.+)`)
	newDomainsFound := 0

	for _, sourceFile := range p.config.DomainProcessing.SourceFiles {
		select {
		case <- ctx.Done():
			return nil, ctx.Err()
		default:
		}
		
		file, err := os.Open(sourceFile.Path)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("[requery] Source file not found, skipping: %s", sourceFile.Path)
				continue
			}
			return nil, fmt.Errorf("failed to open source file %s: %w", sourceFile.Path, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			matches := domainPattern.FindStringSubmatch(scanner.Text())
			if len(matches) > 1 {
				domain := strings.TrimSpace(matches[1])
				if _, exists := domainSet[domain]; !exists {
					domainSet[domain] = struct{}{}
					newDomainsFound++
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading source file %s: %w", sourceFile.Path, err)
		}
	}
	log.Printf("[requery] Found %d new domains from source files. Total unique domains: %d.", newDomainsFound, len(domainSet))

	if len(domainSet) == 0 {
		return []string{}, nil
	}

	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}

	backupData := strings.Join(domains, "\n")
	if err := os.WriteFile(p.config.DomainProcessing.OutputFile, []byte(backupData), 0644); err != nil {
		return nil, fmt.Errorf("failed to write updated backup file %s: %w", p.config.DomainProcessing.OutputFile, err)
	}
	log.Printf("[requery] Successfully wrote %d total domains to backup file.", len(domains))
	
	return domains, nil
}

// resendDNSQueries handles step 6 of the workflow.
func (p *Requery) resendDNSQueries(ctx context.Context, domains []string) error {
	var wg sync.WaitGroup
	ticker := time.NewTicker(time.Second / time.Duration(p.config.ExecutionSettings.QueriesPerSecond))
	defer ticker.Stop()
	
	dnsClient := new(dns.Client)

	for i := 0; i < len(domains); i++ {
		domain := domains[i]
		
		select {
		case <-ticker.C:
		case <-ctx.Done():
			wg.Wait()
			p.setCancelledState("task cancelled by user")
			return ctx.Err()
		}

		wg.Add(2)
		
		go func(qtype uint16) {
			defer wg.Done()
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(domain), qtype)
			_, _, _ = dnsClient.ExchangeContext(ctx, msg, p.config.ExecutionSettings.ResolverAddress)
		}(dns.TypeA)
		
		go func(qtype uint16) {
			defer wg.Done()
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(domain), qtype)
			_, _, _ = dnsClient.ExchangeContext(ctx, msg, p.config.ExecutionSettings.ResolverAddress)
		}(dns.TypeAAAA)

		newProcessed := atomic.AddInt64(&p.config.Status.Progress.Processed, 1)
		if newProcessed%100 == 0 || int(newProcessed) == len(domains) {
			p.mu.Lock()
			_ = p.saveConfigUnlocked()
			p.mu.Unlock()
		}
	}

	wg.Wait()
	return nil
}

// ----------------------------------------------------------------------------
// 4. API Handlers
// ----------------------------------------------------------------------------

func (p *Requery) api() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/", p.handleGetConfig)
	r.Get("/status", p.handleGetStatus)
	r.Post("/trigger", p.handleTriggerTask)
	r.Post("/cancel", p.handleCancelTask)
	r.Post("/scheduler/config", p.handleUpdateScheduler)
	r.Get("/stats/source_file_counts", p.handleGetSourceFileCounts)
	r.Post("/clear_backup", p.handleClearBackupFile)

	return r
}

func (p *Requery) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	p.jsonResponse(w, p.config, http.StatusOK)
}

func (p *Requery) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	p.jsonResponse(w, p.config.Status, http.StatusOK)
}

func (p *Requery) handleTriggerTask(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.config.Status.TaskState == "running" {
		p.jsonError(w, "A task is already running.", http.StatusConflict)
		return
	}

	p.taskCtx, p.taskCancel = context.WithCancel(context.Background())
	go p.runTask(p.taskCtx)

	p.jsonResponse(w, map[string]string{"status": "success", "message": "A new task has been started."}, http.StatusOK)
}

func (p *Requery) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config.Status.TaskState != "running" || p.taskCancel == nil {
		p.jsonError(w, "No running task to cancel.", http.StatusNotFound)
		return
	}
	
	p.taskCancel()
	log.Println("[requery] Task cancellation requested via API.")
	
	p.jsonResponse(w, map[string]string{"status": "success", "message": "Task cancellation initiated."}, http.StatusOK)
}

func (p *Requery) handleUpdateScheduler(w http.ResponseWriter, r *http.Request) {
	var newSchedulerConf SchedulerConfig
    if err := json.NewDecoder(r.Body).Decode(&newSchedulerConf); err != nil {
        p.jsonError(w, "Invalid JSON body", http.StatusBadRequest)
        return
    }

	p.mu.Lock()
	defer p.mu.Unlock()

	p.config.Scheduler = newSchedulerConf
	if err := p.saveConfigUnlocked(); err != nil {
		p.jsonError(w, "Failed to save updated config", http.StatusInternalServerError)
		return
	}
	p.rescheduleTasks()
	p.jsonResponse(w, map[string]string{"status": "success", "message": "Scheduler configuration updated successfully."}, http.StatusOK)
}

func (p *Requery) handleClearBackupFile(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.config.Status.TaskState == "running" {
		p.jsonError(w, "Cannot clear backup file while a task is running.", http.StatusConflict)
		return
	}

	filePath := p.config.DomainProcessing.OutputFile
	if err := os.Truncate(filePath, 0); err != nil {
		if !os.IsNotExist(err) {
			p.jsonError(w, "Failed to clear backup file: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	log.Printf("[requery] Backup file %s has been cleared via API.", filePath)
	p.jsonResponse(w, map[string]string{"status": "success", "message": "Backup file has been cleared."}, http.StatusOK)
}

func (p *Requery) handleGetSourceFileCounts(w http.ResponseWriter, r *http.Request) {
	log.Println("[requery] API: Getting source file counts...")
	if err := p.callURLs(r.Context(), p.config.URLActions.SaveRules); err != nil {
		p.jsonError(w, "Failed to save rules before counting: "+err.Error(), http.StatusInternalServerError)
		return
	}

	type fileCount struct {
		Alias string `json:"alias"`
		Count int    `json:"count"`
	}

	counts := make([]fileCount, 0, len(p.config.DomainProcessing.SourceFiles))
	domainPattern := regexp.MustCompile(`^full:(.+)`)

	for _, sourceFile := range p.config.DomainProcessing.SourceFiles {
		count := 0
		file, err := os.Open(sourceFile.Path)
		if err != nil {
			if os.IsNotExist(err) {
				counts = append(counts, fileCount{Alias: sourceFile.Alias, Count: 0})
				continue
			}
			p.jsonError(w, "Failed to read source file "+sourceFile.Path+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if domainPattern.MatchString(scanner.Text()) {
				count++
			}
		}
		if err := scanner.Err(); err != nil {
			p.jsonError(w, "Error while scanning file "+sourceFile.Path+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		counts = append(counts, fileCount{Alias: sourceFile.Alias, Count: count})
	}
	
	p.jsonResponse(w, map[string]any{"status": "success", "data": counts}, http.StatusOK)
}

// ----------------------------------------------------------------------------
// 5. Helper and Utility Functions
// ----------------------------------------------------------------------------

func (p *Requery) loadConfig() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	dataBytes, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[requery] config file %s not found, initializing with default empty config.", p.filePath)
			p.config = &Config{Status: Status{TaskState: "idle"}}
			return p.saveConfigUnlocked()
		}
		return err
	}
	
	var cfg Config
	if err := json.Unmarshal(dataBytes, &cfg); err != nil {
		return fmt.Errorf("failed to parse json from config file %s: %w", p.filePath, err)
	}
	p.config = &cfg

	if p.config.Status.TaskState == "" {
		p.config.Status.TaskState = "idle"
	}
	if p.config.ExecutionSettings.URLCallDelayMS == 0 {
		p.config.ExecutionSettings.URLCallDelayMS = 50 // Default value
	}
	if p.config.ExecutionSettings.QueriesPerSecond == 0 {
		p.config.ExecutionSettings.QueriesPerSecond = 100 // Default value
	}

	return nil
}

func (p *Requery) saveConfigUnlocked() error {
	dataBytes, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config to json: %w", err)
	}

	tmpFile := p.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, dataBytes, 0644); err != nil {
		return fmt.Errorf("failed to write to temporary config file: %w", err)
	}
	if err := os.Rename(tmpFile, p.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to rename temporary config file: %w", err)
	}

	return nil
}

// [FIX] Corrected rescheduleTasks logic
func (p *Requery) rescheduleTasks() {
	if err := p.setupScheduler(); err != nil {
		log.Printf("[requery] WARN: Failed to reschedule tasks: %v", err)
	}
}

// [FIX] Completely rebuilt setupScheduler to correctly handle start_datetime
func (p *Requery) setupScheduler() error {
	// Remove all previous jobs from the running scheduler instance
    for _, entry := range p.scheduler.Entries() {
        p.scheduler.Remove(entry.ID)
    }

	if !p.config.Scheduler.Enabled || p.config.Scheduler.IntervalMinutes <= 0 {
		log.Println("[requery] Scheduler is disabled in config.")
		return nil
	}

	// The function to be executed by the scheduler
	jobFunc := func() {
		log.Println("[requery] Scheduler is triggering a task.")
		p.mu.Lock()
		defer p.mu.Unlock()

		if p.config.Status.TaskState == "running" {
			log.Println("[requery] Scheduler skipped: previous task is still running.")
			return
		}
		
		p.taskCtx, p.taskCancel = context.WithCancel(context.Background())
		go p.runTask(p.taskCtx)
	}
	
	// If StartDatetime is set and is in the future, schedule a one-time run.
	if p.config.Scheduler.StartDatetime != "" {
		startTime, err := time.Parse(time.RFC3339, p.config.Scheduler.StartDatetime)
		if err != nil {
			log.Printf("[requery] WARN: Invalid start_datetime format, ignoring: %v", err)
		} else if time.Now().UTC().Before(startTime) {
			delay := time.Until(startTime)
			log.Printf("[requery] Scheduling first run in %v at %v.", delay, startTime)
			
			time.AfterFunc(delay, func() {
				// Execute the job for the first time
				jobFunc()
				
				// After the first run, schedule the recurring job
				p.mu.Lock()
				defer p.mu.Unlock()
				p.rescheduleTasks() // Re-call to set up the recurring job
			})
			return nil // The recurring job will be set up after the first run
		}
	}

	// If StartDatetime is in the past or not set, start the recurring job immediately.
	spec := fmt.Sprintf("@every %dm", p.config.Scheduler.IntervalMinutes)
	_, err := p.scheduler.AddFunc(spec, jobFunc)
	if err != nil {
		return fmt.Errorf("failed to add cron job with spec '%s': %w", spec, err)
	}

	log.Printf("[requery] Scheduler job added/updated with spec: %s", spec)
	return nil
}

func (p *Requery) callURLs(ctx context.Context, urls []string) error {
	delay := time.Duration(p.config.ExecutionSettings.URLCallDelayMS) * time.Millisecond
	for i, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request for %s: %w", url, err)
		}
		
		resp, err := p.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to call URL %s: %w", url, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("bad response from URL %s: status %d, body: %s", url, resp.StatusCode, string(body))
		}
		
		_, _ = io.Copy(io.Discard, resp.Body)

		if i < len(urls)-1 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func (p *Requery) readDomainsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

func (p *Requery) setFailedState(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config.Status.TaskState = "failed"
	log.Printf("[requery] ERROR: Task failed: "+format, args...)
}

func (p *Requery) setCancelledState(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config.Status.TaskState = "cancelled"
	log.Println("[requery] INFO: Task cancelled:", reason)
}

func (p *Requery) jsonResponse(w http.ResponseWriter, data any, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[requery] ERROR: failed to encode response: %v", err)
	}
}

func (p *Requery) jsonError(w http.ResponseWriter, message string, code int) {
	p.jsonResponse(w, map[string]string{"status": "error", "message": message}, code)
}
