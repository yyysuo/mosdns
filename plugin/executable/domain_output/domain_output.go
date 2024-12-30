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

package domain_output

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
)

const PluginType = "domain_output"

func init() {
	// Register this plugin type with its initialization funcs.
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })

	// Register a quick setup function for sequence.
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

// Args contains configuration for the plugin.
type Args struct {
	FilePath   string `yaml:"file_path"`   // Path to the output file.
	MaxEntries uint   `yaml:"max_entries"` // Max number of entries before writing to file.
}

var _ sequence.Executable = (*domainOutput)(nil)

// domainOutput implements handler.ExecutablePlugin.
type domainOutput struct {
	filePath   string
	maxEntries uint
	domainData map[string]uint
	mu         sync.Mutex
}

// Exec implements handler.Executable.
func (d *domainOutput) Exec(ctx context.Context, qCtx *query_context.Context) error {
	// Fetch the queried domain name
	qname := qCtx.QName()

	// Update the domain count
	d.mu.Lock()
	defer d.mu.Unlock()
	d.domainData[qname]++

	// When the number of entries exceeds maxEntries, write to the file
	if len(d.domainData) >= int(d.maxEntries) {
		if err := d.writeToFile(); err != nil {
			return fmt.Errorf("failed to write domain data to file: %v", err)
		}
	}

	return nil
}

// writeToFile writes the current domain statistics to the output file.
func (d *domainOutput) writeToFile() error {
	// Open the file for writing (will overwrite if exists)
	file, err := os.OpenFile(d.filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", d.filePath, err)
	}
	defer file.Close()

	// Write domain stats to the file
	for domain, count := range d.domainData {
		_, err := fmt.Fprintf(file, "%s %d\n", domain, count)
		if err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}

	// Clear the domainData map after writing to file
	d.domainData = make(map[string]uint)

	return nil
}

func Init(_ *coremain.BP, args any) (any, error) {
	// Parse arguments from config
	cfg := args.(*Args)
	return &domainOutput{
		filePath:   cfg.FilePath,
		maxEntries: cfg.MaxEntries,
		domainData: make(map[string]uint),
	}, nil
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	// Quick setup based on a string (could be extended with more logic)
	parts := split(s, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid quick setup format, expected <file_path>,<max_entries>")
	}

	filePath := parts[0]
	maxEntries, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid max_entries value: %v", err)
	}

	return &domainOutput{
		filePath:   filePath,
		maxEntries: uint(maxEntries),
		domainData: make(map[string]uint),
	}, nil
}

// Utility function to split string by a delimiter
func split(s, delimiter string) []string {
	var result []string
	for _, part := range s {
		result = append(result, part)
	}
	return result
}
