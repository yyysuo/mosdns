package tools

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
	"strconv"  // 添加导入
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/IrineSistiana/mosdns/v5/mlog"
)

// 创建新的 resend 子命令
func newResendRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resend",
		Short: "Resend DNS queries to the specified server from a domain list file.",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			filePath := args[0]
			rate := args[1]
			dnsServer := args[2]

			// 解析速率
			ratePerSecond, err := strconv.Atoi(rate)
			if err != nil {
				mlog.S().Fatalf("Invalid rate value: %v", err)
			}

			// 调用 resend 函数
			err = resendQueries(filePath, ratePerSecond, dnsServer)
			if err != nil {
				mlog.S().Fatalf("Error sending DNS queries: %v", err)
			}
		},
	}
}

// 执行域名查询的核心功能
func resendQueries(filePath string, ratePerSecond int, dnsServer string) error {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// 读取域名列表
	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		domains = append(domains, fields[1]) // 只需要域名
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// 计算每秒发送的查询数量
	ticker := time.NewTicker(time.Second / time.Duration(ratePerSecond))
	defer ticker.Stop()

	for _, domain := range domains {
		<-ticker.C // 等待合适的时间间隔
		err := sendDNSQuery(domain, dnsServer)
		if err != nil {
			mlog.S().Errorf("Failed to send DNS query for %s: %v", domain, err)
		}
	}
	mlog.S().Info("DNS queries resent successfully.")
	return nil
}

// 向 DNS 服务器发送查询
func sendDNSQuery(domain string, dnsServer string) error {
	// 构造DNS查询请求
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// 使用UDP连接
	client := new(dns.Client)
	_, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		return fmt.Errorf("failed to send query: %v", err)
	}
	mlog.S().Infof("Query for %s sent successfully.", domain)
	return nil
}
