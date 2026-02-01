@{
    RootModule = 'DNS-HawkEye.psm1'
    ModuleVersion = '5.1.0'
    GUID = 'a1b2c3d4-5678-90ab-cdef-example123456'
    Author = 'Your Name'
    Copyright = '(c) 2024 Your Name. All rights reserved.'
    Description = '🛡️ Advanced DNS diagnostics tool with GFW detection, QPS benchmarking, and intelligent pollution analysis'
    PowerShellVersion = '5.1'
    
    FunctionsToExport = @(
        'Start-DnsHawkEye',
        'Test-DnsResolution', 
        'Test-DnsQps',
        'Export-DnsReport'
    )
    
    PrivateData = @{
        PSData = @{
            Tags = @('DNS', 'Network', 'Security', 'GFW', 'Performance', 'Monitoring')
            LicenseUri = 'https://github.com/yourusername/DNS-HawkEye/blob/main/LICENSE'
            ProjectUri = 'https://github.com/yourusername/DNS-HawkEye'
            IconUri = 'https://raw.githubusercontent.com/yourusername/DNS-HawkEye/main/Assets/icon.png'
            ReleaseNotes = '🚀 Initial release with GFW detection and QPS testing'
        }
    }
}
