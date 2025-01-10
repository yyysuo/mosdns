# mosdns

功能概述、配置方式、教程等，详见: [wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)

下载预编译文件、更新日志，详见: [release](https://github.com/IrineSistiana/mosdns/releases)

docker 镜像: [docker hub](https://hub.docker.com/r/irinesistiana/mosdns)


添加的功能：

一、输出域名列表
  - tag: my_realiplist
    type: domain_output        #输出域名列表
    args:
      file_stat: /cus/mosdns/gen/realiplist.txt   #输出的域名查询统计
      file_rule: /cus/mosdns/gen/realiprule.txt  #生成的分流域名规则
      max_entries: 3000       #达到3000条查询时自动保存到指定目录
      dump_interval: 1800   #每半小时自动保存一次上述统计及规则

生成的域名列表的格式
realiplist.txt
访问次数   域名
0000000054 www.mi.com
0000000039 browser.events.data.microsoft.com
0000000028 dns.msftncsi.com

realiprule.txt
full:www.mi.com
full:browser.events.data.microsoft.com
full:dns.msftncsi.com

二、移除结果中的cname
  - tag: sequence_local_in
    type: sequence
    args:
      - exec: $forward_local
      - matches: has_resp
        exec: cname_remover

三、使用resend将realiplist.txt中的域名发送到指定的dns服务器（tcp）

/cus/bin/mosdns resend resend /cus/mosdns/gen/realiplist.txt 10 10.10.10.1:53

resend为添加的命令，/cus/mosdns/gen/realiplist.txt为本地文件 10为每秒发多少个dns请求 10.10.10.1:53为指定的dns服务器，只支持tcp


