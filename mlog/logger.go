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

package mlog

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
)

type LogConfig struct {
	// Level, See also zapcore.ParseLevel.
	Level string `yaml:"level"`

	// File that logger will be writen into.
	// Default is stderr.
	File string `yaml:"file"`

	// Production enables json output.
	Production bool `yaml:"production"`
}

var (
	stderr = zapcore.Lock(os.Stderr)
	// MODIFIED: Export Lvl to be accessible from other packages.
	// This is now the single point of control for the log level.
	Lvl = zap.NewAtomicLevelAt(zap.InfoLevel)

	// This global logger `l` and `s` will now also be controlled by `Lvl`.
	l   = zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), stderr, Lvl))
	s   = l.Sugar()
	nop = zap.NewNop()
)

func NewLogger(lc LogConfig) (*zap.Logger, error) {
	// MODIFIED: Use the global atomic level Lvl instead of parsing from config here.
	// The initial level is set from the config just once.
	initialLevel, err := zapcore.ParseLevel(lc.Level)
	if err != nil {
		// Fallback to InfoLevel if parsing fails but don't return an error,
		// so the program can start with a default log level.
		initialLevel = zap.InfoLevel
		S().Warnf("invalid log level '%s' in config, falling back to 'info'", lc.Level)
	}
	Lvl.SetLevel(initialLevel) // Set initial level for the global controller.

	var out zapcore.WriteSyncer
	if lf := lc.File; len(lf) > 0 {
		f, _, err := zap.Open(lf)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		out = zapcore.Lock(f)
	} else {
		out = stderr
	}

	// All created loggers will now respect the global `Lvl`.
	if lc.Production {
		return zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), out, Lvl)), nil
	}
	return zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), out, Lvl)), nil
}

// L is a global logger.
func L() *zap.Logger {
	return l
}

// SetLevel sets the log level for the global logger.
// DEPRECATED in favor of directly using Lvl.SetLevel().
func SetLevel(l zapcore.Level) {
	Lvl.SetLevel(l)
}

// S is a global logger.
func S() *zap.SugaredLogger {
	return s
}

// Nop is a logger that never writes out logs.
func Nop() *zap.Logger {
	return nop
}
