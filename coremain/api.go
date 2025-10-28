// /root/mosdns/coremain/api.go
package coremain

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type jsonError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		mlog.L().Error("failed to write json response", zap.Error(err))
	}
}

// RegisterCaptureAPI registers the log capture APIs to the given router.
func RegisterCaptureAPI(router *chi.Mux) {
	router.Post("/api/v1/capture/start", handleStartCapture())
	router.Get("/api/v1/capture/logs", handleGetLogs())
}

func handleStartCapture() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			DurationSeconds int `json:"duration_seconds"`
		}

		// Set default duration
		req.DurationSeconds = 120

		// Decode request body if provided
		if r.Body != http.NoBody {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, jsonError{Error: "invalid request body: " + err.Error()})
				return
			}
		}

		if req.DurationSeconds <= 0 || req.DurationSeconds > 600 {
			writeJSON(w, http.StatusBadRequest, jsonError{Error: "duration must be between 1 and 600 seconds"})
			return
		}

		duration := time.Duration(req.DurationSeconds) * time.Second
		// Use the exported mlog.Lvl
		GlobalLogCollector.StartCapture(duration, mlog.Lvl)

		response := struct {
			Message          string    `json:"message"`
			DurationSeconds  int       `json:"duration_seconds"`
			ExpireTimestamp  time.Time `json:"expire_timestamp"`
			LogLevelElevated bool      `json:"log_level_elevated"`
		}{
			Message:          fmt.Sprintf("log capture started for %d seconds", req.DurationSeconds),
			DurationSeconds:  req.DurationSeconds,
			ExpireTimestamp:  time.Now().Add(duration),
			LogLevelElevated: true,
		}
		writeJSON(w, http.StatusOK, response)
	}
}

func handleGetLogs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logs := GlobalLogCollector.GetLogs()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(logs); err != nil {
			mlog.L().Error("failed to encode logs to client", zap.Error(err))
		}
	}
}
