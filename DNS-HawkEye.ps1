# DNS综合测试套件 v5.0 - 完全优化版
# 功能：DNS解析测试 + QPS性能测试 + 智能分析 + 增强检测

# 配置部分 - 增强版域名列表
$global:Domains = @(
    # 国际社交媒体
    "youtube.com",
    "twitter.com", 
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "tiktok.com",
    "reddit.com",
    "pinterest.com",
    "linkedin.com",
    "snapchat.com",
    "telegram.org",
    "discord.com",
    "twitch.tv",
    
    # 国内主流网站
    "baidu.com",
    "taobao.com",
    "qq.com",
    "sina.com.cn",
    "weibo.com",
    "zhihu.com",
    "jd.com",
    "163.com",
    "sohu.com",
    "360.cn",
    "douyin.com",     # 抖音
    "bilibili.com",   # B站
    "xiaohongshu.com", # 小红书
    "kuaishou.com",   # 快手
    
    # 技术网站
    "github.com",
    "gitlab.com",
    "stackoverflow.com",
    "docker.com",
    "kubernetes.io",
    "npmjs.com",
    "pypi.org",
    "maven.apache.org",
    
    # CDN和云服务
    "cloudflare.com",
    "akamai.com",
    "fastly.com",
    "azure.com",
    "aws.amazon.com",
    "google.com",
    "apple.com",
    "microsoft.com",
    
    # 新闻和维基
    "wikipedia.org",
    "bbc.com",
    "cnn.com",
    "nytimes.com",
    "reuters.com",
    "bloomberg.com"
)

# DNS服务器配置
$global:DnsServers = @{
    # 国内DNS
    "本地DNS"       = "192.168.2.200"
    "阿里DNS"       = "223.6.6.6"
    "腾讯DNS"       = "119.29.29.29"
    "114DNS"       = "114.114.114.114"
    "百度DNS"       = "180.76.76.76"
    "DNS派-电信"    = "101.226.4.6"
    "DNS派-联通"    = "123.125.81.6"
    "DNSPod"        = "119.29.29.29"
    "360DNS"        = "101.198.198.198"
    
    # 国际DNS
    "Cloudflare"    = "1.1.1.1"
    "Google DNS"    = "8.8.8.8"
    "OpenDNS"       = "208.67.222.222"
    "Quad9"         = "9.9.9.9"
    "AdGuard DNS"   = "94.140.14.14"
    "Comodo DNS"    = "8.26.56.26"
    "Verisign DNS"  = "64.6.64.6"
    "Level3 DNS"    = "209.244.0.3"
    "Norton DNS"    = "199.85.126.10"
}

# ============================================
# 增强的ASN数据库（包含GFW混淆IP段检测）
# ============================================

$global:DomainExpectedAS = @{
    # Google/Youtube家族
    "youtube.com"      = @("AS15169", "AS43515", "AS36040", "AS19527")
    "google.com"       = @("AS15169", "AS19527", "AS26910")
    "gmail.com"        = @("AS15169")
    "googleapis.com"   = @("AS15169", "AS36040")
    "ggpht.com"        = @("AS15169")
    
    # Facebook家族
    "facebook.com"     = @("AS32934", "AS54113")
    "instagram.com"    = @("AS32934", "AS54113")
    "whatsapp.com"     = @("AS32934", "AS13335")
    "fbcdn.net"        = @("AS32934")
    
    # Twitter家族
    "twitter.com"      = @("AS13414", "AS35995", "AS63079")
    "twimg.com"        = @("AS13414")
    "t.co"             = @("AS13414")
    
    # TikTok/抖音
    "tiktok.com"       = @("AS137876", "AS398101", "AS139190")
    "douyin.com"       = @("AS137876", "AS139190")
    "douyincdn.com"    = @("AS137876")
    
    # 百度家族
    "baidu.com"        = @("AS4134", "AS4837", "AS9808", "AS23724")
    "baidu.cn"         = @("AS4134", "AS4837")
    "bdstatic.com"     = @("AS23724", "AS45090")
    
    # 腾讯家族
    "qq.com"           = @("AS45090", "AS134238", "AS58461")
    "weixin.qq.com"    = @("AS45090")
    "tencent.com"      = @("AS45090", "AS132203")
    "wechat.com"       = @("AS45090")
    
    # 阿里家族
    "taobao.com"       = @("AS37963", "AS45102", "AS138699")
    "alibaba.com"      = @("AS37963", "AS45102")
    "aliyun.com"       = @("AS37963", "AS45102")
    "tmall.com"        = @("AS37963", "AS138699")
    
    # 新浪家族
    "sina.com.cn"      = @("AS4812", "AS38341", "AS45057")
    "weibo.com"        = @("AS4812", "AS38341")
    "sinaimg.cn"       = @("AS4812", "AS38341")
    
    # 京东
    "jd.com"           = @("AS24424", "AS134963", "AS138714")
    "jdpay.com"        = @("AS24424")
    
    # GitHub
    "github.com"       = @("AS36459", "AS8075")
    "github.io"        = @("AS36459")
    "githubusercontent.com" = @("AS36459")
    
    # Cloudflare
    "cloudflare.com"   = @("AS13335")
    "cloudflare.net"   = @("AS13335")
    
    # Microsoft
    "microsoft.com"    = @("AS8075", "AS12076")
    "azure.com"        = @("AS8075")
    "live.com"         = @("AS8075")
    
    # Amazon/AWS
    "amazon.com"       = @("AS16509", "AS14618", "AS7224")
    "aws.amazon.com"   = @("AS16509")
    
    # Netflix
    "netflix.com"      = @("AS2906", "AS40027", "AS55095")
    
    # Wikipedia
    "wikipedia.org"    = @("AS14907", "AS198471", "AS55644")
    
    # 其他国际
    "reddit.com"       = @("AS54113", "AS54994")
    "discord.com"      = @("AS13335", "AS14061")
    "telegram.org"     = @("AS62041", "AS62014")
    
    # CDN服务
    "akamai.com"       = @("AS16625", "AS20940")
    "fastly.com"       = @("AS54113")
    "cdn77.com"        = @("AS60068")
}

# ============================================
# 增强的IP地理位置和GFW混淆IP数据库
# ============================================

$global:IPGeoDatabase = @{
    # ========== GFW常见混淆IP段 ==========
    # Facebook IP段（常用于污染YouTube/Twitter）
    "31.13."       = @{Country="Ireland"; ISP="Facebook"; Category="GFW-Facebook"}
    "157.240."     = @{Country="Global"; ISP="Facebook"; Category="GFW-Facebook"}
    "129.134."     = @{Country="Global"; ISP="Facebook"; Category="GFW-Facebook"}
    
    # Twitter IP段（常用于污染Facebook）
    "199.16."      = @{Country="USA"; ISP="Twitter"; Category="GFW-Twitter"}
    "199.59.148."  = @{Country="USA"; ISP="Twitter"; Category="GFW-Twitter"}
    "199.96."      = @{Country="USA"; ISP="Twitter"; Category="GFW-Twitter"}
    
    # 其他已知GFW混淆IP段
    "185.86."      = @{Country="Turkey"; ISP="GFW-Proxy"; Category="GFW-Proxy"}
    "192.0.2."     = @{Country="Test-Net"; ISP="Reserved"; Category="GFW-Reserved"}
    "203.98.7."    = @{Country="Australia"; ISP="GFW-Proxy"; Category="GFW-Proxy"}
    "198.143.164." = @{Country="USA"; ISP="GFW-Proxy"; Category="GFW-Proxy"}
    "69.63."       = @{Country="USA"; ISP="Facebook"; Category="GFW-Facebook"}
    "74.125."      = @{Country="USA"; ISP="Google"; Category="GFW-Google"}
    
    # 国内运营商IP段（正常）
    "124.237."     = @{Country="China"; ISP="ChinaNet Hebei"; Category="Normal"}
    "111.63."      = @{Country="China"; ISP="China Mobile Hebei"; Category="Normal"}
    "110.242."     = @{Country="China"; ISP="China Unicom Hebei"; Category="Normal"}
    "119.28."      = @{Country="China"; ISP="Tencent Cloud"; Category="Normal"}
    "120.232."     = @{Country="China"; ISP="China Mobile"; Category="Normal"}
    "121.32."      = @{Country="China"; ISP="China Telecom"; Category="Normal"}
    
    # ========== 国际公司IP段 ==========
    # Google
    "142.250."     = @{Country="USA"; ISP="Google"; Category="Normal"}
    "172.217."     = @{Country="USA"; ISP="Google"; Category="Normal"}
    "216.58."      = @{Country="USA"; ISP="Google"; Category="Normal"}
    
    # Microsoft
    "20.205."      = @{Country="Global"; ISP="Microsoft Azure"; Category="Normal"}
    "13.107."      = @{Country="Global"; ISP="Microsoft"; Category="Normal"}
    "40.112."      = @{Country="Global"; ISP="Microsoft"; Category="Normal"}
    
    # GitHub
    "140.82."      = @{Country="USA"; ISP="GitHub"; Category="Normal"}
    
    # Cloudflare
    "104.16."      = @{Country="Global"; ISP="Cloudflare"; Category="Normal"}
    "172.64."      = @{Country="Global"; ISP="Cloudflare"; Category="Normal"}
    
    # ========== 内网地址 ==========
    "192.168."     = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "10."          = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.16."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.17."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.18."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.19."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.20."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.21."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.22."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.23."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.24."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.25."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.26."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.27."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.28."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.29."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.30."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
    "172.31."      = @{Country="Local"; ISP="Private Network"; Category="Private"}
}

# GFW混淆规则数据库（域名->被污染的IP段映射）
$global:GFWPatterns = @{
    "youtube.com" = @("31.13.", "157.240.", "69.63.", "129.134.", "185.86.")
    "twitter.com" = @("31.13.", "157.240.", "69.63.", "129.134.")
    "facebook.com" = @("199.16.", "199.59.148.", "199.96.", "74.125.", "185.86.")
    "instagram.com" = @("31.13.", "157.240.", "199.16.", "199.59.148.")
    "whatsapp.com" = @("31.13.", "157.240.", "199.16.")
    "tiktok.com" = @("31.13.", "157.240.", "199.16.", "199.59.148.")
    "github.com" = @("31.13.", "157.240.", "199.16.", "185.86.")
    "google.com" = @("31.13.", "157.240.", "199.16.", "185.86.")
    "wikipedia.org" = @("31.13.", "157.240.", "185.86.")
    "reddit.com" = @("31.13.", "157.240.", "199.16.", "185.86.")
}

# ============================================
# 辅助函数
# ============================================

# 修复数组转字符串的问题
function ConvertTo-StringArray {
    param($Array)
    if (-not $Array) { return "" }
    
    if ($Array.GetType().Name -eq "Object[]") {
        return $Array -join "; "
    } elseif ($Array -is [string]) {
        return $Array
    } else {
        return $Array.ToString()
    }
}

# ============================================
# 增强的地理位置查询（带GFW检测）
# ============================================

function Get-IPGeolocationEnhanced {
    param([string]$IP)
    
    # 检查IP格式
    if (-not $IP -or -not ($IP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")) {
        return [PSCustomObject]@{
            Country = "Invalid"
            Region = "Invalid"
            City = "Invalid"
            ISP = "Invalid IP"
            AS = "Unknown"
            ASNumber = $null
            Source = "Invalid"
            Query = $IP
            Category = "Invalid"
        }
    }
    
    # 1. 首先检查内置数据库（优先级最高）
    foreach ($prefix in $global:IPGeoDatabase.Keys | Sort-Object Length -Descending) {
        if ($IP.StartsWith($prefix)) {
            $geo = $global:IPGeoDatabase[$prefix]
            return [PSCustomObject]@{
                Country = $geo.Country
                Region = "Unknown"
                City = "Unknown"
                ISP = $geo.ISP
                AS = "Unknown"
                ASNumber = $null
                Source = "Local Database"
                Query = $IP
                Category = $geo.Category
            }
        }
    }
    
    # 2. 尝试ip-api.com（最准确的免费API）
    try {
        $url = "http://ip-api.com/json/$IP?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 3 -ErrorAction SilentlyContinue
        
        if ($response.status -eq "success") {
            # 检测GFW混淆IP模式
            $category = "Normal"
            $isp = $response.isp
            
            # 检查是否是GFW代理
            if ($response.org -match "GFW|Great Firewall|Proxy|VPN|HostRoyale|DigitalOcean|Vultr|Linode") {
                $category = "GFW-Proxy"
                $isp = "GFW Proxy (" + $response.isp + ")"
            }
            
            return [PSCustomObject]@{
                Country = $response.country
                Region = $response.regionName
                City = $response.city
                ISP = $isp
                AS = $response.as
                ASNumber = if ($response.as -match "AS(\d+)") { $matches[1] } else { $null }
                Source = "ip-api.com"
                Query = $response.query
                Category = $category
            }
        }
    } catch {
        Write-Debug "ip-api.com查询失败: $_"
    }
    
    # 3. 备用API：ipinfo.io
    try {
        $url = "http://ipinfo.io/$IP/json"
        $response = Invoke-RestMethod -Uri $url -TimeoutSec 2 -ErrorAction SilentlyContinue
        
        if ($response) {
            return [PSCustomObject]@{
                Country = $response.country
                Region = $response.region
                City = $response.city
                ISP = $response.org
                AS = if ($response.org -match "AS\d+") { $matches[0] } else { "Unknown" }
                ASNumber = if ($response.org -match "AS(\d+)") { $matches[1] } else { $null }
                Source = "ipinfo.io"
                Query = $response.ip
                Category = if ($response.org -match "GFW|Proxy") { "GFW-Proxy" } else { "Normal" }
            }
        }
    } catch {
        Write-Debug "ipinfo.io查询失败: $_"
    }
    
    # 4. 根据IP段推断
    $ipParts = $IP -split "\."
    $firstOctet = [int]$ipParts[0]
    
    if ($firstOctet -eq 10 -or ($firstOctet -eq 172 -and [int]$ipParts[1] -ge 16 -and [int]$ipParts[1] -le 31) -or ($firstOctet -eq 192 -and [int]$ipParts[1] -eq 168)) {
        return [PSCustomObject]@{
            Country = "Local"
            Region = "Private"
            City = "Private"
            ISP = "Private Network"
            AS = "AS0"
            ASNumber = "0"
            Source = "Private IP"
            Query = $IP
            Category = "Private"
        }
    }
    
    # 5. 所有方法都失败
    return [PSCustomObject]@{
        Country = "Unknown"
        Region = "Unknown"
        City = "Unknown"
        ISP = "Unknown"
        AS = "Unknown"
        ASNumber = $null
        Source = "Failed"
        Query = $IP
        Category = "Unknown"
    }
}

# ============================================
# 增强的DNS解析测试（修复并发问题）
# ============================================

function Test-DnsResolutionEnhanced {
    param(
        [string]$Domain,
        [string]$DnsServer,
        [string]$ServerName,
        [int]$TimeoutMs = 3000
    )
    
    $result = [PSCustomObject]@{
        Domain = $Domain
        DnsServer = $DnsServer
        ServerName = $ServerName
        IP = $null
        TTL = $null
        ResponseTime = $null
        IsSuspicious = $false
        SuspiciousReason = ""
        Country = "Unknown"
        Region = "Unknown"
        City = "Unknown"
        ISP = "Unknown"
        AS = "Unknown"
        ASNumber = $null
        ExpectedAS = if ($global:DomainExpectedAS[$Domain]) { $global:DomainExpectedAS[$Domain] } else { @() }
        ASMatch = $false
        Status = "Unknown"
        Error = $null
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        QueryType = "A"
        IPCategory = "Unknown"
        GFWDetected = $false
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # 使用同步查询，避免Job的开销
        $dnsResult = Resolve-DnsName -Name $Domain -Server $DnsServer -Type A -DnsOnly -ErrorAction Stop -QuickTimeout | Select-Object -First 1
        
        $stopwatch.Stop()
        
        $result.IP = $dnsResult.IPAddress
        $result.TTL = $dnsResult.TTL
        $result.ResponseTime = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
        $result.Status = "Success"
        
        # 获取地理位置信息
        if ($result.IP) {
            $geo = Get-IPGeolocationEnhanced -IP $result.IP
            $result.Country = $geo.Country
            $result.Region = $geo.Region
            $result.City = $geo.City
            $result.ISP = $geo.ISP
            $result.AS = $geo.AS
            $result.ASNumber = $geo.ASNumber
            $result.IPCategory = $geo.Category
        }
        
        # 检查AS匹配
        if ($result.ExpectedAS.Count -gt 0 -and $result.AS) {
            foreach ($expectedAS in $result.ExpectedAS) {
                if ($result.AS -like "*$expectedAS*") {
                    $result.ASMatch = $true
                    break
                }
            }
        }
        
        # 检查可疑IP
        $suspiciousCheck = Test-SuspiciousIPEnhanced -IP $result.IP -Domain $Domain -AS $result.AS -ExpectedAS $result.ExpectedAS
        if ($suspiciousCheck.IsSuspicious) {
            $result.IsSuspicious = $true
            $result.SuspiciousReason = ConvertTo-StringArray $suspiciousCheck.Reason
            $result.GFWDetected = $suspiciousCheck.GFWDetected
        }
        
    } catch {
        $stopwatch.Stop()
        $result.Status = "Failed"
        $result.Error = $_.Exception.Message
        $result.ResponseTime = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
    }
    
    return $result
}

# ============================================
# 增强的可疑IP检测（包含GFW规则）
# ============================================

function Test-SuspiciousIPEnhanced {
    param(
        [string]$IP,
        [string]$Domain,
        [string]$AS,
        [array]$ExpectedAS
    )
    
    $result = @{
        IsSuspicious = $false
        Reason = @()
        GFWDetected = $false
        GFWPattern = $null
    }
    
    # 1. 检查内网地址
    if ($IP -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|0\.)") {
        $result.IsSuspicious = $true
        $result.Reason += "内网/保留地址"
        return $result
    }
    
    # 2. 检查GFW混淆模式
    if ($global:GFWPatterns.ContainsKey($Domain)) {
        foreach ($pattern in $global:GFWPatterns[$Domain]) {
            if ($IP.StartsWith($pattern)) {
                $result.IsSuspicious = $true
                $result.GFWDetected = $true
                $result.GFWPattern = $pattern
                
                # 确定污染类型
                if ($pattern.StartsWith("31.13.") -or $pattern.StartsWith("157.240.") -or $pattern.StartsWith("69.63.")) {
                    $result.Reason += "GFW: Facebook IP污染"
                } elseif ($pattern.StartsWith("199.16.") -or $pattern.StartsWith("199.59.148.") -or $pattern.StartsWith("199.96.")) {
                    $result.Reason += "GFW: Twitter IP污染"
                } elseif ($pattern.StartsWith("185.86.") -or $pattern.StartsWith("203.98.7.")) {
                    $result.Reason += "GFW: 代理服务器污染"
                } else {
                    $result.Reason += "GFW: 已知污染IP段"
                }
                
                # 如果是GFW污染，直接返回，不再进行其他检查
                return $result
            }
        }
    }
    
    # 3. 检查已知异常模式
    $domainLower = $Domain.ToLower()
    
    # YouTube不应解析到Facebook
    if ($domainLower -like "*youtube*") {
        if ($AS -like "*AS32934*" -or $IP -match "^31\.13\." -or $IP -match "^157\.240\." -or $IP -match "^69\.63\.") {
            $result.IsSuspicious = $true
            $result.Reason += "YouTube解析到Facebook服务器"
            $result.GFWDetected = $true
        }
    }
    
    # Twitter不应解析到Facebook
    if ($domainLower -like "*twitter*") {
        if ($AS -like "*AS32934*" -or $IP -match "^31\.13\." -or $IP -match "^157\.240\." -or $IP -match "^69\.63\.") {
            $result.IsSuspicious = $true
            $result.Reason += "Twitter解析到Facebook服务器"
            $result.GFWDetected = $true
        }
    }
    
    # Facebook不应解析到Twitter
    if ($domainLower -like "*facebook*") {
        if ($AS -like "*AS13414*" -or $AS -like "*AS35995*" -or $IP -match "^199\.(59\.148|16\.|96\.)") {
            $result.IsSuspicious = $true
            $result.Reason += "Facebook解析到Twitter服务器"
            $result.GFWDetected = $true
        }
    }
    
    # Google应解析到Google AS
    if ($domainLower -like "*google*") {
        if (-not ($AS -like "*AS15169*" -or $AS -like "*AS19527*" -or $AS -like "*AS26910*")) {
            $result.IsSuspicious = $true
            $result.Reason += "Google域名解析到非Google服务器"
        }
    }
    
    # 4. 检查AS不匹配
    if (-not $result.IsSuspicious -and $ExpectedAS.Count -gt 0 -and $AS -ne "Unknown") {
        $asMatch = $false
        foreach ($expected in $ExpectedAS) {
            if ($AS -like "*$expected*") {
                $asMatch = $true
                break
            }
        }
        
        if (-not $asMatch) {
            $result.IsSuspicious = $true
            $result.Reason += "AS不匹配: 期望[$($ExpectedAS -join '/')], 实际[$AS]"
        }
    }
    
    # 5. 检查地理位置异常（国内域名解析到国外）
    if ($Domain -match "\.(cn|com\.cn|net\.cn|org\.cn|gov\.cn|edu\.cn)$" -and $IP -notmatch "^(36\.|39\.|42\.|49\.|58\.|59\.|60\.|61\.|106\.|110\.|111\.|112\.|113\.|114\.|115\.|116\.|117\.|118\.|119\.|120\.|121\.|122\.|123\.|124\.|125\.|126\.|171\.|175\.|180\.|183\.|202\.|203\.|210\.|211\.|218\.|219\.|220\.|221\.|222\.)") {
        $result.IsSuspicious = $true
        $result.Reason += "国内域名解析到国外IP"
    }
    
    # 6. 检查测试网段
    if ($IP -match "^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|100\.64\.|198\.18\.)") {
        $result.IsSuspicious = $true
        $result.Reason += "文档/测试网段IP"
    }
    
    return $result
}

# ============================================
# 修复的QPS性能测试（使用线程安全集合）
# ============================================

function Test-DnsQps {
    param(
        [string]$DnsServer,
        [string]$ServerName = "Unknown",
        [int]$DurationSeconds = 10,
        [int]$ConcurrentQueries = 5,
        [string[]]$TestDomains = @("google.com", "baidu.com", "youtube.com", "github.com"),
        [switch]$DetailedReport
    )
    
    Write-Host "`n🚀 开始DNS QPS测试: $ServerName ($DnsServer)" -ForegroundColor Cyan
    Write-Host "测试时长: ${DurationSeconds}秒" -ForegroundColor White
    Write-Host "并发查询: ${ConcurrentQueries}个" -ForegroundColor White
    Write-Host "测试域名: $($TestDomains.Count)个" -ForegroundColor White
    
    # 使用线程安全的集合
    $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $responseTimes = [System.Collections.Concurrent.ConcurrentBag[double]]::new()
    
    $queryCount = [ref] 0
    $successCount = [ref] 0
    $errorCount = [ref] 0
    $totalResponseTime = [ref] 0.0
    
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($DurationSeconds)
    
    # 创建运行空间池
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ConcurrentQueries)
    $runspacePool.Open()
    
    # 创建任务列表
    $tasks = New-Object System.Collections.ArrayList
    
    # 初始化任务
    for ($i = 0; $i -lt $ConcurrentQueries; $i++) {
        $domain = $TestDomains[$i % $TestDomains.Count]
        
        $powerShell = [powershell]::Create()
        $powerShell.RunspacePool = $runspacePool
        
        $null = $powerShell.AddScript({
            param($domain, $dnsServer)
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $success = $false
            
            try {
                $null = Resolve-DnsName -Name $domain -Server $dnsServer -Type A -DnsOnly -ErrorAction Stop
                $success = $true
            } catch {
                $success = $false
            }
            
            $stopwatch.Stop()
            
            return [PSCustomObject]@{
                Domain = $domain
                Success = $success
                ResponseTime = $stopwatch.Elapsed.TotalMilliseconds
                Timestamp = Get-Date
            }
        })
        
        $null = $powerShell.AddArgument($domain)
        $null = $powerShell.AddArgument($DnsServer)
        
        $task = [PSCustomObject]@{
            PowerShell = $powerShell
            AsyncResult = $powerShell.BeginInvoke()
            Domain = $domain
        }
        
        $null = $tasks.Add($task)
    }
    
    # 主循环
    while ((Get-Date) -lt $endTime) {
        for ($i = 0; $i -lt $tasks.Count; $i++) {
            $task = $tasks[$i]
            
            if ($task.AsyncResult.IsCompleted) {
                # 获取结果
                try {
                    $result = $task.PowerShell.EndInvoke($task.AsyncResult)
                    $results.Add($result)
                    
                    # 更新统计
                    [System.Threading.Interlocked]::Increment($queryCount) > $null
                    
                    if ($result.Success) {
                        [System.Threading.Interlocked]::Increment($successCount) > $null
                        [System.Threading.Interlocked]::Add($totalResponseTime, $result.ResponseTime) > $null
                        $responseTimes.Add($result.ResponseTime)
                    } else {
                        [System.Threading.Interlocked]::Increment($errorCount) > $null
                    }
                } catch {
                    [System.Threading.Interlocked]::Increment($errorCount) > $null
                } finally {
                    $task.PowerShell.Dispose()
                }
                
                # 创建新任务
                $newDomain = $TestDomains[($queryCount.Value % $TestDomains.Count)]
                
                $newPowerShell = [powershell]::Create()
                $newPowerShell.RunspacePool = $runspacePool
                
                $null = $newPowerShell.AddScript({
                    param($domain, $dnsServer)
                    
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $success = $false
                    
                    try {
                        $null = Resolve-DnsName -Name $domain -Server $dnsServer -Type A -DnsOnly -ErrorAction Stop
                        $success = $true
                    } catch {
                        $success = $false
                    }
                    
                    $stopwatch.Stop()
                    
                    return [PSCustomObject]@{
                        Domain = $domain
                        Success = $success
                        ResponseTime = $stopwatch.Elapsed.TotalMilliseconds
                        Timestamp = Get-Date
                    }
                })
                
                $null = $newPowerShell.AddArgument($newDomain)
                $null = $newPowerShell.AddArgument($DnsServer)
                
                $tasks[$i] = [PSCustomObject]@{
                    PowerShell = $newPowerShell
                    AsyncResult = $newPowerShell.BeginInvoke()
                    Domain = $newDomain
                }
            }
        }
        
        Start-Sleep -Milliseconds 10
    }
    
    # 清理
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    # 计算统计信息
    $elapsedTime = (Get-Date) - $startTime
    $qps = if ($elapsedTime.TotalSeconds -gt 0) { [math]::Round($queryCount.Value / $elapsedTime.TotalSeconds, 2) } else { 0 }
    $successRate = if ($queryCount.Value -gt 0) { [math]::Round(($successCount.Value / $queryCount.Value) * 100, 2) } else { 0 }
    $avgResponseTime = if ($successCount.Value -gt 0) { [math]::Round($totalResponseTime.Value / $successCount.Value, 2) } else { 0 }
    
    # 计算百分位响应时间
    $sortedTimes = $responseTimes | Sort-Object
    $percentile95 = if ($sortedTimes.Count -gt 0) { 
        $index = [math]::Floor($sortedTimes.Count * 0.95)
        [math]::Round($sortedTimes[$index], 2)
    } else { 0 }
    
    $percentile99 = if ($sortedTimes.Count -gt 0) { 
        $index = [math]::Floor($sortedTimes.Count * 0.99)
        [math]::Round($sortedTimes[$index], 2)
    } else { 0 }
    
    # 创建结果对象
    $qpsResult = [PSCustomObject]@{
        ServerName = $ServerName
        DnsServer = $DnsServer
        TotalQueries = $queryCount.Value
        SuccessQueries = $successCount.Value
        ErrorQueries = $errorCount.Value
        SuccessRate = $successRate
        QPS = $qps
        AvgResponseTime = $avgResponseTime
        MinResponseTime = if ($sortedTimes.Count -gt 0) { [math]::Round(($sortedTimes | Measure-Object -Minimum).Minimum, 2) } else { 0 }
        MaxResponseTime = if ($sortedTimes.Count -gt 0) { [math]::Round(($sortedTimes | Measure-Object -Maximum).Maximum, 2) } else { 0 }
        P95ResponseTime = $percentile95
        P99ResponseTime = $percentile99
        TestDuration = [math]::Round($elapsedTime.TotalSeconds, 2)
        ConcurrentQueries = $ConcurrentQueries
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    # 输出结果
    Write-Host "`n📊 QPS测试结果:" -ForegroundColor Green
    Write-Host "总查询数: $($queryCount.Value)" -ForegroundColor White
    Write-Host "成功查询: $($successCount.Value)" -ForegroundColor White
    Write-Host "失败查询: $($errorCount.Value)" -ForegroundColor White
    
    $successColor = if ($successRate -ge 95) { "Green" } elseif ($successRate -ge 80) { "Yellow" } else { "Red" }
    Write-Host "成功率: ${successRate}%" -ForegroundColor $successColor
    
    $qpsColor = if ($qps -ge 100) { "Green" } elseif ($qps -ge 50) { "Yellow" } else { "Red" }
    Write-Host "QPS: ${qps}" -ForegroundColor $qpsColor
    
    Write-Host "平均响应时间: ${avgResponseTime}ms" -ForegroundColor White
    Write-Host "P95响应时间: ${percentile95}ms" -ForegroundColor White
    Write-Host "P99响应时间: ${percentile99}ms" -ForegroundColor White
    
    # 详细报告
    if ($DetailedReport) {
        Write-Host "`n📈 响应时间分布:" -ForegroundColor Yellow
        
        $timeGroups = @{
            "超快 (<10ms)" = ($sortedTimes | Where-Object { $_ -lt 10 }).Count
            "快速 (10-50ms)" = ($sortedTimes | Where-Object { $_ -ge 10 -and $_ -lt 50 }).Count
            "正常 (50-100ms)" = ($sortedTimes | Where-Object { $_ -ge 50 -and $_ -lt 100 }).Count
            "较慢 (100-200ms)" = ($sortedTimes | Where-Object { $_ -ge 100 -and $_ -lt 200 }).Count
            "很慢 (200-500ms)" = ($sortedTimes | Where-Object { $_ -ge 200 -and $_ -lt 500 }).Count
            "超慢 (≥500ms)" = ($sortedTimes | Where-Object { $_ -ge 500 }).Count
        }
        
        foreach ($group in $timeGroups.GetEnumerator()) {
            $percent = if ($successCount.Value -gt 0) { [math]::Round(($group.Value / $successCount.Value) * 100, 1) } else { 0 }
            $bar = "█" * [math]::Round($percent / 2)
            Write-Host "  $($group.Key.PadRight(15)): $($group.Value.ToString().PadRight(6)) [$bar] ${percent}%" -ForegroundColor White
        }
    }
    
    return $qpsResult
}

# ============================================
# 增强的HTML报告生成（支持筛选和排序）
# ============================================

function Generate-EnhancedHtmlReport {
    param(
        $Results,
        [string]$OutputPath = "DNS_Enhanced_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    )
    
    Write-Host "`n📊 生成增强版HTML报告..." -ForegroundColor Yellow
    
    # 准备数据
    $suspiciousCount = ($Results | Where-Object { $_.IsSuspicious -eq $true }).Count
    $gfwCount = ($Results | Where-Object { $_.GFWDetected -eq $true }).Count
    $successCount = ($Results | Where-Object { $_.Status -eq "Success" }).Count
    
    # 创建HTML报告
    $html = @"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS测试报告 v5.0</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.1/css/buttons.dataTables.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/filterizr/2.2.4/filterizr.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #9b59b6;
            --dark-color: #2c3e50;
            --light-color: #ecf0f1;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            margin: 0;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, var(--dark-color), #34495e);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            margin: 0;
            font-size: 2.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }
        
        .header .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
            margin-top: 10px;
        }
        
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: var(--light-color);
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.green { border-left: 5px solid var(--success-color); }
        .stat-card.red { border-left: 5px solid var(--danger-color); }
        .stat-card.blue { border-left: 5px solid var(--primary-color); }
        .stat-card.purple { border-left: 5px solid var(--info-color); }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .filters {
            padding: 20px 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        
        .filter-group {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .filter-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 25px;
            background: white;
            color: var(--dark-color);
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 600;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        
        .filter-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .filter-btn.active {
            background: var(--primary-color);
            color: white;
        }
        
        .filter-btn.suspicious { background: var(--danger-color); color: white; }
        .filter-btn.gfw { background: var(--warning-color); color: white; }
        .filter-btn.success { background: var(--success-color); color: white; }
        .filter-btn.all { background: var(--dark-color); color: white; }
        
        .controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 30px;
            background: white;
            border-bottom: 1px solid #dee2e6;
        }
        
        .search-box {
            flex: 1;
            max-width: 400px;
        }
        
        .search-box input {
            width: 100%;
            padding: 12px 20px;
            border: 2px solid #ddd;
            border-radius: 25px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: var(--primary-color);
        }
        
        .dataTables_wrapper {
            padding: 30px;
        }
        
        table.dataTable {
            width: 100% !important;
            border-collapse: collapse;
        }
        
        table.dataTable thead th {
            background: var(--dark-color);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        
        table.dataTable tbody td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        
        table.dataTable tbody tr:hover {
            background: #f5f9ff;
        }
        
        .status-success { color: var(--success-color); }
        .status-failed { color: var(--danger-color); }
        .status-timeout { color: var(--warning-color); }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: 600;
            margin: 2px;
        }
        
        .badge-suspicious { background: var(--danger-color); color: white; }
        .badge-gfw { background: var(--warning-color); color: white; }
        .badge-normal { background: var(--success-color); color: white; }
        .badge-private { background: #7f8c8d; color: white; }
        
        .country-flag {
            display: inline-block;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 8px;
            vertical-align: middle;
        }
        
        .country-china { background: #ff0000; }
        .country-usa { background: #3c3b6e; }
        .country-ireland { background: #169b62; }
        .country-local { background: #95a5a6; }
        .country-unknown { background: #bdc3c7; }
        
        .footer {
            text-align: center;
            padding: 20px;
            background: var(--dark-color);
            color: white;
            font-size: 14px;
        }
        
        @media (max-width: 768px) {
            .header h1 { font-size: 1.8rem; }
            .stat-card { padding: 15px; }
            .controls { flex-direction: column; gap: 15px; }
            .search-box { max-width: 100%; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-network-wired"></i> DNS测试报告 v5.0</h1>
            <div class="subtitle">
                生成时间: $(Get-Date -Format 'yyyy年MM月dd日 HH:mm:ss') | 
                测试域名: $($Results.Count) 个 | 
                DNS服务器: $(($Results | Select-Object -Unique ServerName).Count) 个
            </div>
        </div>
        
        <div class="stats-container">
            <div class="stat-card green">
                <i class="fas fa-check-circle fa-2x"></i>
                <div class="stat-number">$successCount</div>
                <div>成功解析</div>
            </div>
            <div class="stat-card red">
                <i class="fas fa-exclamation-triangle fa-2x"></i>
                <div class="stat-number">$suspiciousCount</div>
                <div>可疑解析</div>
            </div>
            <div class="stat-card purple">
                <i class="fas fa-shield-alt fa-2x"></i>
                <div class="stat-number">$gfwCount</div>
                <div>GFW检测</div>
            </div>
            <div class="stat-card blue">
                <i class="fas fa-server fa-2x"></i>
                <div class="stat-number">$(($Results | Select-Object -Unique ServerName).Count)</div>
                <div>DNS服务器</div>
            </div>
        </div>
        
        <div class="filters">
            <div class="filter-group">
                <button class="filter-btn all active" data-filter="all">全部 ($($Results.Count))</button>
                <button class="filter-btn suspicious" data-filter="suspicious">可疑 ($suspiciousCount)</button>
                <button class="filter-btn gfw" data-filter="gfw">GFW污染 ($gfwCount)</button>
                <button class="filter-btn success" data-filter="success">成功 ($successCount)</button>
                <button class="filter-btn" data-filter="failed">失败 ($(($Results | Where-Object { $_.Status -ne "Success" }).Count))</button>
            </div>
        </div>
        
        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="搜索域名、IP、DNS服务器或国家...">
            </div>
            <div>
                <button id="exportBtn" class="filter-btn blue"><i class="fas fa-download"></i> 导出CSV</button>
            </div>
        </div>
        
        <div class="dataTables_wrapper">
            <table id="resultsTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>域名</th>
                        <th>DNS服务器</th>
                        <th>IP地址</th>
                        <th>国家</th>
                        <th>ISP/AS</th>
                        <th>状态</th>
                        <th>延迟</th>
                        <th>TTL</th>
                        <th>标记</th>
                    </tr>
                </thead>
                <tbody>
"@

    # 填充表格数据
    foreach ($result in $Results) {
        # 状态图标
        $statusIcon = if ($result.Status -eq "Success") { 
            "<i class='fas fa-check-circle status-success'></i>" 
        } elseif ($result.Status -eq "Timeout") { 
            "<i class='fas fa-clock status-timeout'></i>" 
        } else { 
            "<i class='fas fa-times-circle status-failed'></i>" 
        }
        
        # 国家图标
        $countryClass = switch -Wildcard ($result.Country) {
            "*China*" { "country-china" }
            "*USA*" { "country-usa" }
            "*Ireland*" { "country-ireland" }
            "*Local*" { "country-local" }
            default { "country-unknown" }
        }
        
        $countryDisplay = if ($result.Country -eq "China") { 
            "<span class='country-flag $countryClass'></span>中国" 
        } elseif ($result.Country -eq "USA") { 
            "<span class='country-flag $countryClass'></span>美国" 
        } elseif ($result.Country -eq "Ireland") { 
            "<span class='country-flag $countryClass'></span>爱尔兰" 
        } elseif ($result.Country -eq "Local") { 
            "<span class='country-flag $countryClass'></span>内网" 
        } else { 
            "<span class='country-flag $countryClass'></span>$($result.Country)" 
        }
        
        # 标记
        $badges = ""
        if ($result.IsSuspicious -eq $true) {
            $badges += "<span class='badge badge-suspicious'>可疑</span>"
        }
        if ($result.GFWDetected -eq $true) {
            $badges += "<span class='badge badge-gfw'>GFW</span>"
        }
        if ($result.ASMatch -eq $true) {
            $badges += "<span class='badge badge-normal'>AS匹配</span>"
        }
        if ($result.IPCategory -eq "Private") {
            $badges += "<span class='badge badge-private'>内网</span>"
        }
        
        # ISP/AS信息
        $asInfo = if ($result.AS -ne "Unknown") { 
            $shortAS = if ($result.AS -match "AS\d+") { $matches[0] } else { $result.AS }
            "$($result.ISP)<br><small>$shortAS</small>" 
        } else { 
            $result.ISP 
        }
        
        # 可疑原因
        $suspiciousReason = if ($result.SuspiciousReason) { 
            "title='$($result.SuspiciousReason)'" 
        } else { "" }
        
        $html += @"
                    <tr data-status="$($result.Status.ToLower())" data-suspicious="$($result.IsSuspicious)" data-gfw="$($result.GFWDetected)" $suspiciousReason>
                        <td><strong>$($result.Domain)</strong></td>
                        <td>$($result.ServerName)<br><small>$($result.DnsServer)</small></td>
                        <td><code>$($result.IP)</code></td>
                        <td>$countryDisplay</td>
                        <td>$asInfo</td>
                        <td>$statusIcon $($result.Status)</td>
                        <td>$($result.ResponseTime)ms</td>
                        <td>$($result.TTL)s</td>
                        <td>$badges</td>
                    </tr>
"@
    }

    $html += @"
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>DNS测试报告 v5.0 | 生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | 总记录数: $($Results.Count)</p>
            <p><small>© 2024 DNS测试工具 | 数据仅供参考，请遵守当地法律法规</small></p>
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.1/js/dataTables.buttons.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.1/js/buttons.html5.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/filterizr/2.2.4/filterizr.min.js"></script>
    
    <script>
        $(document).ready(function() {
            // 初始化DataTable
            var table = $('#resultsTable').DataTable({
                pageLength: 50,
                lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, '全部']],
                language: {
                    url: 'https://cdn.datatables.net/plug-ins/1.13.6/i18n/zh-CN.json'
                },
                dom: 'Bfrtip',
                buttons: [
                    {
                        extend: 'csv',
                        text: '<i class="fas fa-file-csv"></i> 导出CSV',
                        className: 'btn btn-primary',
                        exportOptions: {
                            columns: [0,1,2,3,4,5,6,7,8]
                        }
                    }
                ]
            });
            
            // 搜索功能
            $('#searchInput').on('keyup', function() {
                table.search(this.value).draw();
            });
            
            // 筛选功能
            $('.filter-btn').on('click', function() {
                var filter = $(this).data('filter');
                
                // 更新按钮状态
                $('.filter-btn').removeClass('active');
                $(this).addClass('active');
                
                // 应用筛选
                if (filter === 'all') {
                    table.search('').draw();
                } else if (filter === 'suspicious') {
                    table.column(8).search('可疑').draw();
                } else if (filter === 'gfw') {
                    table.column(8).search('GFW').draw();
                } else if (filter === 'success') {
                    table.column(5).search('Success').draw();
                } else if (filter === 'failed') {
                    table.column(5).search('Failed|Timeout').draw();
                }
            });
            
            // 导出按钮
            $('#exportBtn').on('click', function() {
                table.button('.buttons-csv').trigger();
            });
            
            // 行点击事件
            $('#resultsTable tbody').on('click', 'tr', function() {
                $(this).toggleClass('selected');
            });
        });
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "✅ 增强版HTML报告已生成: $OutputPath" -ForegroundColor Green
    
    # 尝试打开报告
    try {
        Start-Process $OutputPath
    } catch {
        Write-Host "无法自动打开报告，请手动打开文件" -ForegroundColor Yellow
    }
    
    return $OutputPath
}

# ============================================
# 批量DNS QPS测试（修复版）
# ============================================

function Test-DnsQpsBatch {
    param(
        [hashtable]$Servers = $global:DnsServers,
        [int]$DurationSeconds = 10,
        [int]$ConcurrentQueries = 8,
        [string[]]$TestDomains = @("google.com", "baidu.com", "youtube.com", "github.com", "qq.com", "taobao.com"),
        [switch]$ExportCSV,
        [switch]$GenerateChart
    )
    
    Write-Host "🚀 开始批量DNS QPS测试" -ForegroundColor Cyan
    Write-Host "测试服务器: $($Servers.Count) 个" -ForegroundColor White
    Write-Host "测试时长: ${DurationSeconds}秒/服务器" -ForegroundColor White
    Write-Host "并发数: ${ConcurrentQueries}" -ForegroundColor White
    Write-Host "测试域名: $($TestDomains.Count)个" -ForegroundColor White
    
    $allResults = @()
    $serverCount = $Servers.Count
    $currentServer = 1
    
    foreach ($serverEntry in $Servers.GetEnumerator()) {
        Write-Host "`n[$currentServer/$serverCount] 测试 $($serverEntry.Key) ($($serverEntry.Value)) ..." -ForegroundColor Yellow
        
        try {
            $result = Test-DnsQps -DnsServer $serverEntry.Value `
                                  -ServerName $serverEntry.Key `
                                  -DurationSeconds $DurationSeconds `
                                  -ConcurrentQueries $ConcurrentQueries `
                                  -TestDomains $TestDomains
            
            $allResults += $result
        } catch {
            Write-Host "  测试失败: $_" -ForegroundColor Red
            $errorResult = [PSCustomObject]@{
                ServerName = $serverEntry.Key
                DnsServer = $serverEntry.Value
                TotalQueries = 0
                SuccessQueries = 0
                ErrorQueries = 1
                SuccessRate = 0
                QPS = 0
                AvgResponseTime = 0
                MinResponseTime = 0
                MaxResponseTime = 0
                P95ResponseTime = 0
                P99ResponseTime = 0
                TestDuration = $DurationSeconds
                ConcurrentQueries = $ConcurrentQueries
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            $allResults += $errorResult
        }
        
        $currentServer++
        
        # 短暂休息，避免连续测试压力过大
        if ($currentServer -le $serverCount) {
            Write-Host "  休息2秒..." -ForegroundColor Gray
            Start-Sleep -Seconds 2
        }
    }
    
    # 生成比较报告
    Write-Host "`n🏆 DNS QPS性能排行榜" -ForegroundColor Green
    
    # 移除失败的结果
    $validResults = $allResults | Where-Object { $_.TotalQueries -gt 0 }
    
    if ($validResults.Count -eq 0) {
        Write-Host "没有有效的QPS测试结果！" -ForegroundColor Red
        return $null
    }
    
    # QPS排名
    Write-Host "`n[按QPS排名]:" -ForegroundColor Yellow
    $qpsRank = $validResults | Sort-Object QPS -Descending | Select-Object -First 10
    $rank = 1
    foreach ($item in $qpsRank) {
        $medal = switch ($rank) {
            1 { "🥇" }
            2 { "🥈" }
            3 { "🥉" }
            default { "$rank." }
        }
        
        $color = if ($rank -eq 1) { "Green" } elseif ($rank -le 3) { "Yellow" } else { "White" }
        
        Write-Host "  $medal $($item.ServerName.PadRight(15)): $($item.QPS.ToString("0.0").PadLeft(6)) QPS | $($item.AvgResponseTime.ToString("0.0").PadLeft(6))ms | $($item.SuccessRate.ToString("0.0").PadLeft(5))%" -ForegroundColor $color
        $rank++
    }
    
    # 导出CSV
    if ($ExportCSV) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = "DNS_QPS_Results_$timestamp.csv"
        $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n📄 QPS测试结果已保存到: $csvPath" -ForegroundColor Green
    }
    
    return $allResults
}

# ============================================
# 主执行函数
# ============================================

function Start-DnsComprehensiveTest {
    param(
        [switch]$RunBasicTest,
        [switch]$RunQpsTest,
        [switch]$RunFullTest,
        [string[]]$CustomDomains,
        [hashtable]$CustomServers,
        [switch]$GenerateHtml
    )
    
    Clear-Host
    Write-Host "🚀 DNS综合测试套件 v5.0" -ForegroundColor Cyan
    Write-Host "📅 系统时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host "💻 PowerShell版本: $($PSVersionTable.PSVersion)" -ForegroundColor White
    
    # 检查网络连接
    Write-Host "`n🌐 检查网络连接..." -ForegroundColor Yellow
    try {
        $pingResult = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -ErrorAction SilentlyContinue
        if ($pingResult) {
            Write-Host "  网络连接正常" -ForegroundColor Green
        } else {
            Write-Host "  网络连接可能有问题" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  网络检查失败" -ForegroundColor Yellow
    }
    
    # 选择测试模式
    if ($RunBasicTest) {
        Write-Host "`n🔍 运行基础DNS解析测试..." -ForegroundColor Yellow
        $results = @()
        
        # 测试前5个DNS服务器和10个域名（快速测试）
        $testServers = $global:DnsServers.GetEnumerator() | Select-Object -First 5
        $testDomains = $global:Domains | Select-Object -First 10
        
        foreach ($server in $testServers) {
            Write-Host "`n测试 $($server.Key) ($($server.Value))..." -ForegroundColor Cyan
            
            foreach ($domain in $testDomains) {
                Write-Host "  $domain" -NoNewline
                
                $result = Test-DnsResolutionEnhanced -Domain $domain -DnsServer $server.Value -ServerName $server.Key
                $results += $result
                
                $color = if ($result.IsSuspicious) { "Red" } elseif ($result.Status -eq "Success") { "Green" } else { "Gray" }
                $icon = if ($result.IsSuspicious) { "⚠" } elseif ($result.Status -eq "Success") { "✓" } else { "✗" }
                
                Write-Host " $icon $($result.IP)" -ForegroundColor $color
            }
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = "DNS_Basic_Results_$timestamp.csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        
        Write-Host "`n✅ 基础测试完成！结果保存到: $csvPath" -ForegroundColor Green
        
        if ($GenerateHtml) {
            Generate-EnhancedHtmlReport -Results $results
        }
        
    } elseif ($RunQpsTest) {
        Write-Host "`n⚡ 运行DNS QPS性能测试..." -ForegroundColor Yellow
        $qpsResults = Test-DnsQpsBatch -DurationSeconds 10 -ConcurrentQueries 5 -ExportCSV
        
    } elseif ($RunFullTest) {
        Write-Host "`n🚀 运行完整DNS测试..." -ForegroundColor Yellow
        Write-Host "测试域名: $($global:Domains.Count) 个" -ForegroundColor White
        Write-Host "DNS服务器: $($global:DnsServers.Count) 个" -ForegroundColor White
        
        $allResults = @()
        $totalTests = $global:Domains.Count * $global:DnsServers.Count
        $completed = 0
        
        foreach ($server in $global:DnsServers.GetEnumerator()) {
            Write-Host "`n测试 $($server.Key) ($($server.Value))..." -ForegroundColor Cyan
            
            foreach ($domain in $global:Domains) {
                $completed++
                $percent = [math]::Round(($completed / $totalTests) * 100, 1)
                Write-Progress -Activity "DNS测试进行中" -Status "$percent% 完成" -PercentComplete $percent
                
                $result = Test-DnsResolutionEnhanced -Domain $domain -DnsServer $server.Value -ServerName $server.Key
                $allResults += $result
                
                $color = if ($result.IsSuspicious) { "Red" } elseif ($result.Status -eq "Success") { "Green" } else { "Gray" }
                $icon = if ($result.IsSuspicious) { "⚠" } elseif ($result.Status -eq "Success") { "✓" } else { "✗" }
                
                $status = switch ($result.Status) {
                    "Success" { "$($result.IP)" }
                    "Timeout" { "超时" }
                    default { "失败" }
                }
                
                Write-Host "  $icon $domain → $status" -ForegroundColor $color
            }
        }
        
        Write-Progress -Activity "DNS测试进行中" -Completed
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = "DNS_Full_Results_$timestamp.csv"
        $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        
        Write-Host "`n✅ 完整测试完成！结果保存到: $csvPath" -ForegroundColor Green
        
        if ($GenerateHtml) {
            Generate-EnhancedHtmlReport -Results $allResults
        }
        
        # 显示统计信息
        $suspiciousCount = ($allResults | Where-Object { $_.IsSuspicious -eq $true }).Count
        $gfwCount = ($allResults | Where-Object { $_.GFWDetected -eq $true }).Count
        $successCount = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
        $successRate = [math]::Round(($successCount / $totalTests) * 100, 2)
        
        Write-Host "`n📊 测试统计:" -ForegroundColor Cyan
        Write-Host "  总测试数: $totalTests" -ForegroundColor White
        Write-Host "  成功数: $successCount ($successRate%)" -ForegroundColor $(if($successRate -ge 80){"Green"}else{"Red"})
        Write-Host "  可疑解析: $suspiciousCount" -ForegroundColor $(if($suspiciousCount -eq 0){"Green"}else{"Red"})
        Write-Host "  GFW检测: $gfwCount" -ForegroundColor $(if($gfwCount -eq 0){"Green"}else{"Yellow"})
        
    } else {
        Write-Host "`n请选择测试模式:" -ForegroundColor Yellow
        Write-Host "1. 基础DNS测试（快速）" -ForegroundColor White
        Write-Host "2. QPS性能测试" -ForegroundColor White
        Write-Host "3. 完整DNS测试" -ForegroundColor White
        Write-Host "Q. 退出" -ForegroundColor Gray
        
        $choice = Read-Host "`n请输入选择 (1-3/Q)"
        
        switch ($choice) {
            "1" { Start-DnsComprehensiveTest -RunBasicTest -GenerateHtml }
            "2" { Start-DnsComprehensiveTest -RunQpsTest }
            "3" { Start-DnsComprehensiveTest -RunFullTest -GenerateHtml }
            "Q" { Write-Host "再见！" -ForegroundColor Green; exit }
            default { Write-Host "无效选择！" -ForegroundColor Red }
        }
    }
}

# ============================================
# 启动脚本
# ============================================

# 检查PowerShell版本
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "需要 PowerShell 5.0 或更高版本" -ForegroundColor Red
    exit
}

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "⚠️  建议以管理员身份运行以获得更准确的结果" -ForegroundColor Yellow
}

# 显示欢迎信息
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "      DNS综合测试套件 v5.0" -ForegroundColor Cyan
Write-Host "      增强版 | 支持GFW检测" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`n功能特性:" -ForegroundColor Yellow
Write-Host "  ✓ DNS解析准确性测试" -ForegroundColor Green
Write-Host "  ✓ GFW污染检测" -ForegroundColor Green
Write-Host "  ✓ ASN验证和匹配" -ForegroundColor Green
Write-Host "  ✓ QPS性能测试（已修复）" -ForegroundColor Green
Write-Host "  ✓ 增强的HTML报告（支持筛选排序）" -ForegroundColor Green
Write-Host "  ✓ 内置IP/ASN数据库" -ForegroundColor Green
Write-Host "`n按任意键开始测试..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# 启动主测试
Start-DnsComprehensiveTest
