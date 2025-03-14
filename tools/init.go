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

package tools

import (
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/spf13/cobra"
)

func init() {
	// 创建 probe 命令
	probeCmd := &cobra.Command{
		Use:   "probe",
		Short: "Run some server tests.",
	}
	probeCmd.AddCommand(
		newConnReuseCmd(),
		newIdleTimeoutCmd(),
		newPipelineCmd(),
	)
	coremain.AddSubCmd(probeCmd)

	// 创建 config 命令
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Tools that can generate/convert mosdns config file.",
	}
	configCmd.AddCommand(newGenCmd(), newConvCmd())
	coremain.AddSubCmd(configCmd)

	// 创建 resend 命令
	resendCmd := &cobra.Command{
		Use:   "resend",
		Short: "Resend DNS queries from a domain list file to the specified server.",
	}
	resendCmd.AddCommand(newResendRunCmd())  // 更改为新的子命令
	coremain.AddSubCmd(resendCmd)}
