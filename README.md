# 🦅 **DNS-HawkEye**
### **Advanced DNS diagnostics suite with GFW detection and QPS benchmarking**

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg" alt="PowerShell">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/github/stars/kekai2020/DNS-HawkEye?style=social" alt="Stars">
</p>

> 🛡️ **企业级DNS诊断套件** - 智能识别GFW污染、精准测量QPS性能、可视化分析报告

![Demo](./Assets/demo.png)

---

## **✨ 核心特性**

**1.** 🔍 **智能DNS解析** - 支持50+ DNS服务器对比测试  
**2.** 🛡️ **GFW污染检测** - 自动识别Facebook/Twitter IP混淆策略  
**3.** ⚡ **QPS性能测试** - 并发压力测试，精准测量服务器性能  
**4.** 📊 **可视化报告** - 交互式HTML报告，支持筛选/排序  
**5.** 🌍 **地理位置分析** - 内置IP地理位置数据库  
**6.** 🔢 **ASN验证** - 校验域名解析结果是否符合预期AS号  

---

## **📋 功能详情**

### **1️⃣ 智能DNS解析**
- ✅ **支持 10+ 主流DNS服务商**（Cloudflare、Google、阿里、腾讯等）
- ✅ **多维度对比分析**（延迟、TTL、地理位置）
- ✅ **自动识别内网/保留地址异常**

### **2️⃣ GFW污染检测**
- ✅ **IP黑名单匹配**：识别Facebook、Twitter IP段污染
- ✅ **ASN验证**：校验解析结果是否符合域名所属AS号
- ✅ **交叉验证**：多DNS服务器结果对比，标记异常解析

### **3️⃣ QPS性能测试**
- ✅ **RunspacePool并发引擎**：支持100+并发查询
- ✅ **毫秒级精度**：统计P50/P95/P99响应延迟
- ✅ **稳定性评估**：成功率、超时率、错误分类统计

### **4️⃣ 可视化报告**
- ✅ **交互式HTML**：Bootstrap 5 + Chart.js 响应式设计
- ✅ **实时筛选**：支持域名、IP、DNS服务器模糊搜索
- ✅ **多维度排序**：点击表头即可排序（延迟、QPS、成功率）
- ✅ **风险标记**：红色高亮可疑解析，黄色标记GFW干扰

---

## **🚀 快速开始**

### **1. 安装**
```powershell
# 克隆仓库
git clone https://github.com/kekai2020/DNS-HawkEye.git
cd DNS-HawkEye

# 导入模块
Import-Module .\DNS-HawkEye.psd1 -Force

# 开始测试
Start-DnsHawkEye -Full -Html
```

### **2. 使用示例**
```powershell
# 基础测试（快速）
Start-DnsHawkEye -Basic

# QPS性能测试（10秒，5并发）
Start-DnsHawkEye -Qps -QpsDuration 10 -QpsConcurrent 5

# 完整测试并生成HTML报告
Start-DnsHawkEye -Full -Html
```

---

## **📊 报告预览**

**生成的HTML报告包含：**
1. **实时搜索与多条件筛选**
2. **GFW污染标记与可疑分析**
3. **性能排行榜可视化图表**
4. **响应时间分布直方图**

---

## **🏗️ 技术架构**

**1. 并发引擎：** 基于RunspacePool的高性能并发  
**2. 检测算法：** 多维度ASN验证 + GFW IP段黑名单  
**3. 报告引擎：** 原生HTML5 + Bootstrap 5 + Chart.js  

---

## **🤝 Contributing**

欢迎提交Issue和PR！

---

## **📝 License**
详见 [LICENSE](LICENSE) 文件
