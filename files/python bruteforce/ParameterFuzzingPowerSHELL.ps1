# Parameter Fuzzer - PowerShell Version (FULLY FIXED)
# Usage: .\param_fuzzer.ps1 -URL "https://example.com/page?id=FUZZ" -Wordlist "wordlist.txt"

param(
    [Parameter(Mandatory=$true)]
    [string]$URL,
    
    [Parameter(Mandatory=$true)]
    [string]$Wordlist,
    
    [string]$Parameter = $null,
    [int]$Threads = 10,
    [double]$Delay = 0,
    [string]$Method = "GET"
)

# Create results directory
$reportsDir = "FuzzerReports"
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir | Out-Null
    Write-Host "[+] Created reports directory: $reportsDir" -ForegroundColor Green
}

class FuzzResult {
    [string]$ParameterValue
    [string]$Url
    [int]$Status
    [long]$Size
    [string]$ContentType
    [double]$ResponseTime
    [string]$Redirect
    [string]$Server
    [string]$Title
}

class ParameterFuzzer {
    [string]$BaseUrl
    [string]$WordlistFile
    [int]$Threads
    [double]$Delay
    [string]$Method
    [string]$ParamName
    [System.Collections.ArrayList]$AllResults
    [System.Collections.ArrayList]$InterestingResults
    [datetime]$StartTime
    [hashtable]$Headers
    [string]$ReportsDir
    [int]$TotalTested
    
    ParameterFuzzer([string]$url, [string]$wordlist, [int]$threads, [double]$delay, [string]$method, [string]$param, [string]$reportsDir) {
        $this.BaseUrl = $url.TrimEnd('/')
        $this.WordlistFile = $wordlist
        $this.Threads = $threads
        $this.Delay = $delay
        $this.Method = $method.ToUpper()
        $this.AllResults = [System.Collections.ArrayList]@()
        $this.InterestingResults = [System.Collections.ArrayList]@()
        $this.ReportsDir = $reportsDir
        $this.TotalTested = 0
        
        $this.Headers = @{
            'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        if ($param) {
            $this.ParamName = $param
        } else {
            $this.ParamName = $this.DetectParamName()
        }
    }
    
    [string]DetectParamName() {
        if ($this.BaseUrl -match 'FUZZ') {
            return 'FUZZ'
        }
        
        if ($this.BaseUrl -match '\?(.+?)=') {
            return $matches[1]
        }
        
        return 'id'
    }
    
    [string]BuildUrl([string]$value) {
        if ($this.BaseUrl -match 'FUZZ') {
            return $this.BaseUrl -replace 'FUZZ', $value -replace 'fuzz', $value
        }
        
        if ($this.BaseUrl -match '=$') {
            return "$($this.BaseUrl)$value"
        } elseif ($this.BaseUrl -match '=') {
            return $this.BaseUrl -replace '=.*', "=$value"
        } else {
            return "$($this.BaseUrl)?$($this.ParamName)=$value"
        }
    }
    
    [void]TestParameter([string]$word) {
        $word = $word.Trim()
        
        if ([string]::IsNullOrEmpty($word) -or $word.StartsWith('#')) {
            return
        }
        
        $this.TotalTested++
        
        if ($this.Delay -gt 0) {
            Start-Sleep -Milliseconds ($this.Delay * 1000)
        }
        
        $url = $this.BuildUrl($word)
        
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            # Suppress SSL errors
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
            
            $response = $null
            $statusCode = 0
            $size = 0
            $contentType = "N/A"
            $redirect = ""
            $server = "N/A"
            $title = "N/A"
            
            try {
                if ($this.Method -eq 'GET') {
                    # PS 5.1 compatible - catch all errors
                    $response = Invoke-WebRequest -Uri $url -Headers $this.Headers -TimeoutSec 10 -ErrorAction Continue
                } else {
                    $response = Invoke-WebRequest -Uri $url -Method $this.Method -Headers $this.Headers -TimeoutSec 10 -ErrorAction Continue
                }
                
                if ($response) {
                    $statusCode = $response.StatusCode
                    $size = $response.RawContentLength
                    if ($null -eq $size) {
                        $size = $response.Content.Length
                    }
                    $contentType = $response.Headers['Content-Type'] -join ', '
                    $redirect = $response.Headers['Location'] -join ', '
                    $server = $response.Headers['Server'] -join ', '
                    $title = $this.ExtractTitle($response.Content)
                }
                
            } catch {
                # Extract status code from error if available
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    $size = $_.Exception.Response.ContentLength
                    if ($null -eq $size -or $size -lt 0) {
                        $size = 0
                    }
                    $contentType = $_.Exception.Response.Headers['Content-Type'] -join ', '
                    $redirect = $_.Exception.Response.Headers['Location'] -join ', '
                    $server = $_.Exception.Response.Headers['Server'] -join ', '
                } else {
                    $statusCode = 0
                    $size = 0
                }
            }
            
            $stopwatch.Stop()
            $responseTime = $stopwatch.Elapsed.TotalMilliseconds
            
            # Save ALL results
            $result = [FuzzResult]@{
                ParameterValue = $word
                Url = $url
                Status = $statusCode
                Size = $size
                ContentType = $contentType
                ResponseTime = [Math]::Round($responseTime, 2)
                Redirect = $redirect
                Server = $server
                Title = $title
            }
            
            $this.AllResults.Add($result) | Out-Null
            
            # Check if interesting
            if ($this.IsInteresting($statusCode, $size)) {
                $color = $this.GetColor($statusCode)
                Write-Host "[+] [$statusCode] Size: $($size.ToString().PadLeft(7)) | $word" -ForegroundColor $color
                $this.InterestingResults.Add($result) | Out-Null
            } else {
                Write-Host "[-] [$statusCode] Size: $($size.ToString().PadLeft(7)) | $word" -ForegroundColor Gray
            }
            
        } catch {
            Write-Host "[!] Error testing '$word' : $($_.Exception.Message)" -ForegroundColor Red
            
            # Still add as failed result
            $result = [FuzzResult]@{
                ParameterValue = $word
                Url = $url
                Status = 0
                Size = 0
                ContentType = "ERROR"
                ResponseTime = 0
                Redirect = ""
                Server = "N/A"
                Title = "Connection Error"
            }
            
            $this.AllResults.Add($result) | Out-Null
        }
    }
    
    [bool]IsInteresting([int]$status, [long]$size) {
        # Interesting responses
        if ($status -in 200, 201, 204, 301, 302, 307, 308, 401, 403) {
            return $true
        }
        if ($size -gt 1000) {
            return $true
        }
        return $false
    }
    
    [string]ExtractTitle([string]$html) {
        try {
            if ($html -match '<title>(.*?)</title>') {
                $title = $matches[1].Trim()
                if ($title.Length -gt 100) {
                    return $title.Substring(0, 100)
                }
                return $title
            }
        } catch {
            # Ignore
        }
        return 'N/A'
    }
    
    [string]GetColor([int]$status) {
        if ($status -eq 200 -or $status -eq 201) {
            return 'Green'
        }
        if ($status -eq 301 -or $status -eq 302) {
            return 'Yellow'
        }
        if ($status -eq 401 -or $status -eq 403) {
            return 'Cyan'
        }
        if ($status -eq 0) {
            return 'Red'
        }
        return 'White'
    }
    
    [string]GetStatusColor([int]$status) {
        if ($status -in 200, 201, 204) {
            return '#d4edda'
        }
        if ($status -in 301, 302, 307, 308) {
            return '#fff3cd'
        }
        if ($status -in 401, 403) {
            return '#cce5ff'
        }
        if ($status -eq 0) {
            return '#f8d7da'
        }
        return '#e2e3e5'
    }
    
    [void]Run() {
        if (-not (Test-Path $this.WordlistFile)) {
            Write-Host "[ERROR] Wordlist file '$($this.WordlistFile)' not found!" -ForegroundColor Red
            return
        }
        
        $words = @(Get-Content $this.WordlistFile | Where-Object { $_ -and -not $_.StartsWith('#') })
        
        if ($words.Count -eq 0) {
            Write-Host "[ERROR] No words found in wordlist!" -ForegroundColor Red
            return
        }
        
        Write-Host ""
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host "[*] Target: $($this.BaseUrl)" -ForegroundColor Cyan
        Write-Host "[*] Parameter: $($this.ParamName)" -ForegroundColor Cyan
        Write-Host "[*] Wordlist: $($this.WordlistFile) ($($words.Count) values)" -ForegroundColor Cyan
        Write-Host "[*] Method: $($this.Method)" -ForegroundColor Cyan
        Write-Host "[*] Reports Dir: $($this.ReportsDir)" -ForegroundColor Cyan
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host ""
        
        $this.StartTime = Get-Date
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Process each word
        $count = 0
        foreach ($word in $words) {
            $this.TestParameter($word)
            $count++
            
            if ($count % 5 -eq 0) {
                Write-Host "[*] Progress: $count/$($words.Count)" -ForegroundColor Gray
            }
        }
        
        $stopwatch.Stop()
        $elapsed = $stopwatch.Elapsed.TotalSeconds
        
        Write-Host ""
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host "[*] Finished in $([Math]::Round($elapsed, 2)) seconds" -ForegroundColor Cyan
        Write-Host "[*] Total tested: $($this.TotalTested)" -ForegroundColor Cyan
        Write-Host "[*] Interesting: $($this.InterestingResults.Count)" -ForegroundColor Cyan
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host ""
        
        # Save reports
        $this.SaveAllResultsHtml($elapsed, $words.Count)
        $this.SaveInterestingResultsHtml($elapsed)
        $this.SaveTextReport()
    }
    
    [void]SaveAllResultsHtml([double]$elapsedTime, [int]$totalWords) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "$($this.ReportsDir)\all_results_$timestamp.html"
        
        $sortedResults = $this.AllResults | Sort-Object { $_.Status }, { -$_.Size }
        
        $tableRows = ""
        $idx = 1
        
        foreach ($result in $sortedResults) {
            $status = [string]$result.Status
            $statusColor = $this.GetStatusColor($result.Status)
            $sizeFormatted = if ($result.Size -gt 0) { "$($result.Size.ToString('N0')) bytes" } else { "0 bytes" }
            
            $tableRows += @"
            <tr>
                <td>$idx</td>
                <td><span class="status-badge" style="background-color: $statusColor;">$status</span></td>
                <td><span class="param-value">$($result.ParameterValue)</span></td>
                <td class="size">$sizeFormatted</td>
                <td class="response-time">$($result.ResponseTime) ms</td>
                <td>$($result.ContentType.Substring(0, [Math]::Min(40, $result.ContentType.Length)))</td>
                <td><a href="$($result.Url)" target="_blank" class="url-link">$($result.Url.Substring(0, [Math]::Min(60, $result.Url.Length)))...</a></td>
            </tr>
"@
            $idx++
        }
        
        $htmlContent = $this.GenerateHtmlTemplate("ALL RESULTS", $sortedResults.Count, $this.TotalTested, $elapsedTime, $tableRows)
        $htmlContent | Out-File -FilePath $filename -Encoding UTF8 -Force
        Write-Host "[+] ALL RESULTS saved to: $filename" -ForegroundColor Green
    }
    
    [void]SaveInterestingResultsHtml([double]$elapsedTime) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "$($this.ReportsDir)\interesting_results_$timestamp.html"
        
        $sortedResults = $this.InterestingResults | Sort-Object { $_.Status }, { -$_.Size }
        
        $tableRows = ""
        $idx = 1
        
        if ($this.InterestingResults.Count -eq 0) {
            $tableRows = '<tr><td colspan="7" style="text-align: center; padding: 50px; color: #999;">No interesting results found</td></tr>'
        } else {
            foreach ($result in $sortedResults) {
                $status = [string]$result.Status
                $statusColor = $this.GetStatusColor($result.Status)
                $sizeFormatted = if ($result.Size -gt 0) { "$($result.Size.ToString('N0')) bytes" } else { "0 bytes" }
                
                $tableRows += @"
            <tr>
                <td>$idx</td>
                <td><span class="status-badge" style="background-color: $statusColor;">$status</span></td>
                <td><span class="param-value">$($result.ParameterValue)</span></td>
                <td class="size">$sizeFormatted</td>
                <td class="response-time">$($result.ResponseTime) ms</td>
                <td>$($result.ContentType.Substring(0, [Math]::Min(40, $result.ContentType.Length)))</td>
                <td><a href="$($result.Url)" target="_blank" class="url-link">$($result.Url.Substring(0, [Math]::Min(60, $result.Url.Length)))...</a></td>
            </tr>
"@
                $idx++
            }
        }
        
        $htmlContent = $this.GenerateHtmlTemplate("INTERESTING RESULTS", $this.InterestingResults.Count, $this.TotalTested, $elapsedTime, $tableRows)
        $htmlContent | Out-File -FilePath $filename -Encoding UTF8 -Force
        Write-Host "[+] INTERESTING RESULTS saved to: $filename" -ForegroundColor Green
    }
    
    [string]GenerateHtmlTemplate([string]$title, [int]$found, [int]$total, [double]$elapsed, [string]$tableRows) {
        $hitRate = if ($total -gt 0) { [Math]::Round(($found / $total * 100), 1) } else { 0 }
        
        return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Parameter Fuzzing - $title</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .url {
            font-size: 1.1em;
            opacity: 0.9;
            margin: 10px 0;
            word-break: break-all;
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 5px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 5px solid #667eea;
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        
        .filters {
            padding: 20px 30px;
            background: white;
            border-bottom: 2px solid #f0f0f0;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        .filters input {
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
            flex: 1;
            min-width: 200px;
        }
        
        .table-wrapper {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: #f8f9fa;
            position: sticky;
            top: 0;
        }
        
        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #555;
            border-bottom: 2px solid #ddd;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #f0f0f0;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .status-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            display: inline-block;
            min-width: 50px;
            text-align: center;
            color: #333;
        }
        
        .url-link {
            color: #667eea;
            text-decoration: none;
            word-break: break-all;
        }
        
        .url-link:hover {
            text-decoration: underline;
        }
        
        .param-value {
            font-family: monospace;
            background: #f8f9fa;
            padding: 3px 8px;
            border-radius: 3px;
            color: #e83e8c;
            font-weight: bold;
        }
        
        .size {
            color: #666;
            font-family: monospace;
            font-weight: 500;
        }
        
        .response-time {
            color: #666;
            font-size: 0.9em;
        }
        
        .footer {
            padding: 20px;
            text-align: center;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
            border-top: 2px solid #f0f0f0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Parameter Fuzzing Report</h1>
            <h2 style="font-size: 1.3em; margin-bottom: 15px;">$title</h2>
            <div class="url">
                <strong>Target:</strong> $($this.BaseUrl)<br>
                <strong>Parameter:</strong> $($this.ParamName)
            </div>
            <p style="font-size: 0.9em; margin-top: 10px;">
                Scan Date: $($this.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
            </p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Results Found</h3>
                <div class="value">$found</div>
            </div>
            <div class="stat-card">
                <h3>Total Tested</h3>
                <div class="value">$total</div>
            </div>
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <div class="value">$([Math]::Round($elapsed, 2))s</div>
            </div>
            <div class="stat-card">
                <h3>Hit Rate</h3>
                <div class="value">$hitRate%</div>
            </div>
        </div>
        
        <div class="filters">
            <input type="text" id="searchInput" placeholder="🔍 Search parameter values or URLs..." onkeyup="filterTable()">
        </div>
        
        <div class="table-wrapper">
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Status Code</th>
                        <th>Parameter</th>
                        <th>Size</th>
                        <th>Response Time</th>
                        <th>Content-Type</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
                    $tableRows
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by PowerShell Parameter Fuzzer | Method: $($this.Method)</p>
        </div>
    </div>
    
    <script>
        function filterTable() {
            let searchInput = document.getElementById('searchInput').value.toLowerCase();
            let table = document.getElementById('resultsTable');
            let tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {
                let td = tr[i].getElementsByTagName('td');
                let paramValue = td[2].textContent.toLowerCase();
                let url = td[6].textContent.toLowerCase();
                
                if (paramValue.includes(searchInput) || url.includes(searchInput)) {
                    tr[i].style.display = '';
                } else {
                    tr[i].style.display = 'none';
                }
            }
        }
    </script>
</body>
</html>
"@
    }
    
    [void]SaveTextReport() {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "$($this.ReportsDir)\summary_$timestamp.txt"
        
        $content = @"
=================================================================
PARAMETER FUZZING REPORT SUMMARY
=================================================================

Target URL: $($this.BaseUrl)
Parameter: $($this.ParamName)
Scan Date: $($this.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))

STATISTICS:
-----------
Total Parameters Tested: $($this.TotalTested)
Interesting Results: $($this.InterestingResults.Count)
All Results Logged: $($this.AllResults.Count)

INTERESTING RESULTS:
---------------------
"@
        
        if ($this.InterestingResults.Count -gt 0) {
            foreach ($result in $this.InterestingResults) {
                $content += "[$($result.Status)] $($result.ParameterValue) - $($result.Url) ($($result.Size) bytes)`r`n"
            }
        } else {
            $content += "No interesting results found`r`n"
        }
        
        $content += @"

=================================================================
For detailed results, see:
- all_results_$timestamp.html (ALL requests)
- interesting_results_$timestamp.html (Only interesting responses)
=================================================================
"@
        
        $content | Out-File -FilePath $filename -Encoding UTF8 -Force
        Write-Host "[+] Summary saved to: $filename" -ForegroundColor Green
    }
}

# Main execution
try {
    Write-Host ""
    Write-Host "PowerShell Parameter Fuzzer" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    $fuzzer = [ParameterFuzzer]::new($URL, $Wordlist, $Threads, $Delay, $Method, $Parameter, $reportsDir)
    $fuzzer.Run()
    
    Write-Host ""
    Write-Host "All reports saved in: $(Resolve-Path $reportsDir)" -ForegroundColor Green
    Write-Host ""
    
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[TRACE] $($_.Exception.StackTrace)" -ForegroundColor Red
    exit 1
}
