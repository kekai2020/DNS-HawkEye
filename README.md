# DNS-HawkEye
Advanced DNS diagnostics suite with GFW detection and QPS benchmarking
# 🦅 DNS-HawkEye

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/yourusername/DNS-HawkEye?style=social)](https://github.com/yourusername/DNS-HawkEye/stargazers)

&gt; 🛡️ **企业级DNS诊断套件** - 智能识别GFW污染、精准测量QPS性能、可视化分析报告

![Demo](./Assets/demo.png)

## ✨ 核心特性

- 🔍 **智能DNS解析** - 支持50+ DNS服务器对比测试
- 🛡️ **GFW污染检测** - 自动识别Facebook/Twitter IP混淆策略
- ⚡ **QPS性能测试** - 并发压力测试，精准测量服务器性能
- 📊 **可视化报告** - 交互式HTML报告，支持筛选/排序
- 🌍 **地理位置分析** - 内置IP地理位置数据库
- 🔢 **ASN验证** - 校验域名解析结果是否符合预期AS号

## 🚀 快速开始

### 安装
```powershell
# 克隆仓库
git clone https://github.com/kekai2020/DNS-HawkEye.git
cd DNS-HawkEye

# 导入模块
Import-Module .\DNS-HawkEye.psd1 -Force

# 开始测试
Start-DnsHawkEye -Full -Html
