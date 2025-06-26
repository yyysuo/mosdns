package switcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
)

const PluginType = "switch"

// globalRegistry a thread-safe registry for all switch instances.
var globalRegistry = struct {
	sync.RWMutex
	instances map[string]*Switch
}{
	instances: make(map[string]*Switch),
}

// Args defines the configuration for a switch instance.
type Args struct {
	// Name is a unique identifier for this switch instance.
	// It's used in match clauses, e.g., `switch "my_switch:on"`.
	Name string `yaml:"name"`

	// StateFilePath is the path to the file that persists the switch's state.
	StateFilePath string `yaml:"state_file_path"`
}

// Switch represents a single, named switch instance.
type Switch struct {
	mutex    sync.RWMutex
	value    string
	filePath string
	name     string
}

// Register the plugin with mosdns core.
func init() {
	sequence.MustRegMatchQuickSetup(PluginType, QuickSetup)
	coremain.RegNewPluginFunc(
		PluginType,
		Init,
		func() any { return new(Args) },
	)
}

// Init creates and initializes a new Switch instance based on config.
func Init(bp *coremain.BP, args any) (any, error) {
	cfg := args.(*Args)

	if cfg.Name == "" {
		return nil, fmt.Errorf("plugin '%s' requires a non-empty 'name'", PluginType)
	}
	if cfg.StateFilePath == "" {
		return nil, fmt.Errorf("plugin '%s' (name: %s) requires a 'state_file_path'", PluginType, cfg.Name)
	}

	sw := &Switch{
		filePath: cfg.StateFilePath,
		name:     cfg.Name,
	}

	// Get a SugaredLogger for convenient, printf-style logging.
	// THIS IS THE FIX: added .Sugar()
	logger := bp.L().Sugar()

	// Ensure the directory for the state file exists.
	if err := os.MkdirAll(filepath.Dir(sw.filePath), 0755); err != nil {
		return nil, fmt.Errorf("cannot create dir for switch file '%s': %w", sw.filePath, err)
	}

	// Load existing state from file.
	data, err := os.ReadFile(sw.filePath)
	if err == nil {
		sw.value = strings.TrimSpace(string(data))
		// Now logger.Infof will work correctly.
		logger.Infof("Switch '%s' loaded initial value '%s' from %s", sw.name, sw.value, sw.filePath)
	} else if os.IsNotExist(err) {
		// If file does not exist, initialize with an empty value.
		sw.value = ""
		if err := os.WriteFile(sw.filePath, []byte(sw.value), 0644); err != nil {
			// Now logger.Warnf will work correctly.
			logger.Warnf("Failed to write initial state for switch '%s' to %s: %v", sw.name, sw.filePath, err)
		} else {
			// Now logger.Infof will work correctly.
			logger.Infof("Switch '%s' initialized with empty value, state file created at %s", sw.name, sw.filePath)
		}
	} else {
		// Other read errors.
		return nil, fmt.Errorf("failed to read switch file '%s': %w", sw.filePath, err)
	}

	// Register the instance to the global registry.
	globalRegistry.Lock()
	defer globalRegistry.Unlock()
	if _, exists := globalRegistry.instances[sw.name]; exists {
		return nil, fmt.Errorf("duplicate switch name detected: '%s'", sw.name)
	}
	globalRegistry.instances[sw.name] = sw

	// Register API endpoints for this instance.
	// The API will be available at /api/plugins/{tag}/...
	bp.RegAPI(sw.Api())

	return sw, nil
}

// Exec for a switch plugin is a no-op, as its logic is in the Matcher.
func (s *Switch) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	return next.ExecNext(ctx, qCtx)
}

// Api sets up and returns the HTTP routes for managing the switch's state.
func (s *Switch) Api() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/", s.handleGetValue)
	r.Put("/", s.handleUpdateValue)
	r.Post("/", s.handleUpdateValue) // Also accept POST for convenience
	return r
}

// handleGetValue handles GET requests to fetch the current switch value.
func (s *Switch) handleGetValue(w http.ResponseWriter, r *http.Request) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, s.value)
}

// handleUpdateValue handles PUT/POST requests to update the switch value.
func (s *Switch) handleUpdateValue(w http.ResponseWriter, r *http.Request) {
	var newVal string

	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON body. Expected format: {\"value\": \"new_value\"}", http.StatusBadRequest)
			return
		}
		newVal = body.Value
	} else if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		newVal = r.FormValue("value")
	} else {
		// Default to reading raw body as value for simple curl requests
		// e.g., curl -X PUT -d 'new_value' http://...
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		newVal = string(body)
	}

	// Atomically update the state.
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 1. First, try to persist to file.
	if err := os.WriteFile(s.filePath, []byte(newVal), 0644); err != nil {
		http.Error(w, "Failed to write to state file: "+err.Error(), http.StatusInternalServerError)
		return // Important: do not update in-memory value if persistence fails.
	}

	// 2. Only update in-memory value after successful persistence.
	s.value = newVal

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Switch '%s' updated to: %s\n", s.name, newVal)
}

// QuickSetup parses the raw string from a match clause.
// Expected format: "switch_name:expected_value"
func QuickSetup(_ sequence.BQ, raw string) (sequence.Matcher, error) {
	// Trim quotes that might be added by YAML parsers.
	cleanRaw := strings.Trim(raw, `"'`)
	
	parts := strings.SplitN(cleanRaw, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid switch matcher format: '%s'. Expected 'name:value'", cleanRaw)
	}
	return &Matcher{name: parts[0], expectedValue: parts[1]}, nil
}

// Matcher implements the sequence.Matcher interface.
type Matcher struct {
	name          string
	expectedValue string
}

// Match performs the actual comparison.
func (m *Matcher) Match(_ context.Context, _ *query_context.Context) (bool, error) {
	globalRegistry.RLock()
	instance, ok := globalRegistry.instances[m.name]
	globalRegistry.RUnlock()

	if !ok {
		// This is a configuration error. The switch name used in the matcher
		// does not correspond to any configured switch instance.
		// We return false to prevent query failures, but a log at startup
		// would be ideal (though harder to implement in Matcher).
		return false, fmt.Errorf("switch with name '%s' not found", m.name)
	}

	instance.mutex.RLock()
	defer instance.mutex.RUnlock()

	return instance.value == m.expectedValue, nil
}
