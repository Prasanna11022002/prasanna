# Parameter Fuzzer - PowerShell Version
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

# Classes and Functions
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
    [int]$Words
    [int]$Lines
}

class ParameterFuzzer {
    [string]$BaseUrl
    [string]$WordlistFile
    [int]$Threads
    [double]$Delay
    [string]$Method
    [string]$ParamName
    [System.Collections.ArrayList]$FoundResults
    [datetime]$StartTime
    [hashtable]$Headers
    
    ParameterFuzzer([string]$url, [string]$wordlist, [int]$threads, [double]$delay, [string]$method, [string]$param) {
        $this.BaseUrl = $url.TrimEnd('/')
        $this.WordlistFile = $wordlist
        $this.Threads = $threads
        $this.Delay = $delay
        $this.Method = $method.ToUpper()
        $this.FoundResults = [System.Collections.ArrayList]@()
        
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
        
        # Try to extract from URL
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
        
        if ($this.Delay -gt 0) {
            Start-Sleep -Milliseconds ($this.Delay * 1000)
        }
        
        $url = $this.BuildUrl($word)
        
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            if ($this.Method -eq 'GET') {
                $response = Invoke-WebRequest -Uri $url -Headers $this.Headers -TimeoutSec 10 -SkipHttpErrorCheck
            } elseif ($this.Method -eq 'POST') {
                $body = @{ $this.ParamName = $word }
                $response = Invoke-WebRequest -Uri $url -Method POST -Body $body -Headers $this.Headers -TimeoutSec 10 -SkipHttpErrorCheck
            } else {
                $response = Invoke-WebRequest -Uri $url -Method $this.Method -Headers $this.Headers -TimeoutSec 10 -SkipHttpErrorCheck
            }
            
            $stopwatch.Stop()
            $responseTime = $stopwatch.Elapsed.TotalMilliseconds
            
            $status = $response.StatusCode
            $size = $response.RawContentLength
            $contentType = $response.Headers['Content-Type'] -join ', '
            
            if ($this.IsInteresting($status, $size)) {
                $color = $this.GetColor($status)
                
                Write-Host "[+] [$status] Size: $($size.ToString().PadLeft(7)) | $word -> $($url.Substring(0, [Math]::Min(80, $url.Length)))" -ForegroundColor $color
                
                $title = $this.ExtractTitle($response.Content)
                $words = $response.Content.Split([Environment]::NewLine).Count
                $lines = ($response.Content -split '\n').Count
                
                $result = [FuzzResult]@{
                    ParameterValue = $word
                    Url = $url
                    Status = $status
                    Size = $size
                    ContentType = $contentType
                    ResponseTime = [Math]::Round($responseTime, 2)
                    Redirect = $response.Headers['Location'] -join ', '
                    Server = $response.Headers['Server'] -join ', '
                    Title = $title
                    Words = $words
                    Lines = $lines
                }
                
                $this.FoundResults.Add($result) | Out-Null
            }
            
        } catch {
            # Silently handle errors
        }
    }
    
    [bool]IsInteresting([int]$status, [long]$size) {
        if ($status -in 200, 201, 204, 301, 302, 307, 308, 401, 403, 500, 502, 503) {
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
            # Ignore errors
        }
        return 'N/A'
    }
    
    [string]GetColor([int]$status) {
        switch ($status) {
            {$_ -eq 200} { return 'Green' }
            {$_ -in 301, 302, 307, 308} { return 'Yellow' }
            {$_ -in 401, 403} { return 'Cyan' }
            {$_ -ge 500} { return 'Red' }
            default { return 'White' }
        }
    }
    
    [void]Run() {
        if (-not (Test-Path $this.WordlistFile)) {
            Write-Host "[ERROR] Wordlist file '$($this.WordlistFile)' not found!" -ForegroundColor Red
            return
        }
        
        $words = @(Get-Content $this.WordlistFile | Where-Object { $_ -and -not $_.StartsWith('#') })
        
        Write-Host ""
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host "[*] Target: $($this.BaseUrl)" -ForegroundColor Cyan
        Write-Host "[*] Parameter: $($this.ParamName)" -ForegroundColor Cyan
        Write-Host "[*] Wordlist: $($this.WordlistFile) ($($words.Count) values)" -ForegroundColor Cyan
        Write-Host "[*] Threads: $($this.Threads)" -ForegroundColor Cyan
        Write-Host "[*] Method: $($this.Method)" -ForegroundColor Cyan
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host ""
        
        $this.StartTime = Get-Date
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Create scriptblock for parallel execution
        $scriptblock = {
            param($fuzzer, $word)
            $fuzzer.TestParameter($word)
        }
        
        # Run fuzzing
        $words | ForEach-Object -Parallel $scriptblock -ArgumentList $this, $_ -ThrottleLimit $this.Threads
        
        $stopwatch.Stop()
        $elapsed = $stopwatch.Elapsed.TotalSeconds
        
        Write-Host ""
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host "[*] Finished in $([Math]::Round($elapsed, 2)) seconds" -ForegroundColor Cyan
        Write-Host "[*] Found $($this.FoundResults.Count) interesting responses" -ForegroundColor Cyan
        Write-Host "=" * 70 -ForegroundColor Cyan
        Write-Host ""
        
        $this.SaveHtmlReport($elapsed, $words.Count)
        $this.SaveTextReport()
    }
    
    [void]SaveHtmlReport([double]$elapsedTime, [int]$totalWords) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "parameter_fuzz_report_$timestamp.html"
        
        $sortedResults = $this.FoundResults | Sort-Object { $_.Status }, { -$_.Size }
        
        $statusCounts = @{}
        foreach ($result in $this.FoundResults) {
            $status = [string]$result.Status
            if (-not $statusCounts.ContainsKey($status)) {
                $statusCounts[$status] = 0
            }
            $statusCounts[$status]++
        }
        
        $tableRows = ""
        $idx = 1
        
        if ($this.FoundResults.Count -eq 0) {
            $tableRows = '<tr><td colspan="9" style="text-align: center; padding: 50px; color: #999;">No interesting results found</td></tr>'
        } else {
            foreach ($result in $sortedResults) {
                $status = [string]$result.Status
                $redirectInfo = if ($result.Redirect) { " → $($result.Redirect.Substring(0, [Math]::Min(30, $result.Redirect.Length)))..." } else { "" }
                
                $tableRows += @"
            <tr>
                <td>$idx</td>
                <td><span class="status-badge status-$status">$status</span></td>
                <td><span class="param-value">$($result.ParameterValue)</span></td>
                <td class="size">$($result.Size.ToString('N0')) bytes</td>
                <td>$($result.Words)</td>
                <td>$($result.Lines)</td>
                <td class="response-time">$($result.ResponseTime) ms</td>
                <td>$($result.Title.Substring(0, [Math]::Min(50, $result.Title.Length)))</td>
                <td><a href="$($result.Url)" target="_blank" class="url-link">$($result.Url.Substring(0, [Math]::Min(60, $result.Url.Length)))...</a>$redirectInfo</td>
            </tr>
"@
                $idx++
            }
        }
        
        $statusOptions = ""
        foreach ($status in ($statusCounts.Keys | Sort-Object)) {
            $statusOptions += "<option value=`"$status`">$status ($($statusCounts[$status]))</option>`n"
        }
        
        $hitRate = if ($totalWords -gt 0) { [Math]::Round(($this.FoundResults.Count / $totalWords * 100), 1) } else { 0 }
        
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Parameter Fuzzing Report - $($this.ParamName)</title>
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
            font-size: 1.2em;
            opacity: 0.9;
            margin: 10px 0;
            word-break: break-all;
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 5px;
        }
        
        .header .param {
            font-size: 1em;
            opacity: 0.8;
            margin-top: 10px;
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
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .stat-card .value {
            font-size: 2em;
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
            align-items: center;
        }
        
        .filters input {
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
            flex: 1;
            min-width: 200px;
        }
        
        .filters select {
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
            cursor: pointer;
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
            cursor: pointer;
            user-select: none;
        }
        
        th:hover {
            background: #e9ecef;
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
            min-width: 60px;
            text-align: center;
        }
        
        .status-200 { background: #d4edda; color: #155724; }
        .status-201 { background: #d4edda; color: #155724; }
        .status-204 { background: #d4edda; color: #155724; }
        .status-301 { background: #fff3cd; color: #856404; }
        .status-302 { background: #fff3cd; color: #856404; }
        .status-307 { background: #fff3cd; color: #856404; }
        .status-308 { background: #fff3cd; color: #856404; }
        .status-401 { background: #cce5ff; color: #004085; }
        .status-403 { background: #cce5ff; color: #004085; }
        .status-405 { background: #e2e3e5; color: #383d41; }
        .status-500 { background: #f8d7da; color: #721c24; }
        .status-502 { background: #f8d7da; color: #721c24; }
        .status-503 { background: #f8d7da; color: #721c24; }
        
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
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Parameter Fuzzing Report</h1>
            <div class="url">$($this.BaseUrl)</div>
            <div class="param">Fuzzing Parameter: <strong>$($this.ParamName)</strong></div>
            <p style="font-size: 0.9em; margin-top: 10px;">
                Scan Date: $($this.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
            </p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Interesting Results</h3>
                <div class="value">$($this.FoundResults.Count)</div>
            </div>
            <div class="stat-card">
                <h3>Total Values Tested</h3>
                <div class="value">$totalWords</div>
            </div>
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <div class="value">$([Math]::Round($elapsedTime, 2))s</div>
            </div>
            <div class="stat-card">
                <h3>Hit Rate</h3>
                <div class="value">$hitRate%</div>
            </div>
        </div>
        
        <div class="filters">
            <input type="text" id="searchInput" placeholder="🔍 Search parameter values..." onkeyup="filterTable()">
            <select id="statusFilter" onchange="filterTable()">
                <option value="">All Status Codes</option>
                $statusOptions
            </select>
        </div>
        
        <div style="overflow-x: auto;">
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">#</th>
                        <th onclick="sortTable(1)">Status ▼</th>
                        <th onclick="sortTable(2)">Parameter Value</th>
                        <th onclick="sortTable(3)">Size</th>
                        <th onclick="sortTable(4)">Words</th>
                        <th onclick="sortTable(5)">Lines</th>
                        <th onclick="sortTable(6)">Response Time</th>
                        <th onclick="sortTable(7)">Title</th>
                        <th onclick="sortTable(8)">URL</th>
                    </tr>
                </thead>
                <tbody>
                    $tableRows
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by Parameter Fuzzer (PowerShell) | Method: $($this.Method) | Threads: $($this.Threads)</p>
        </div>
    </div>
    
    <script>
        function filterTable() {
            let searchInput = document.getElementById('searchInput').value.toLowerCase();
            let statusFilter = document.getElementById('statusFilter').value;
            let table = document.getElementById('resultsTable');
            let tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {
                let td = tr[i].getElementsByTagName('td');
                let paramValue = td[2].textContent.toLowerCase();
                let status = td[1].textContent.trim();
                
                let matchSearch = paramValue.includes(searchInput);
                let matchStatus = statusFilter === '' || status === statusFilter;
                
                if (matchSearch && matchStatus) {
                    tr[i].style.display = '';
                } else {
                    tr[i].style.display = 'none';
                }
            }
        }
        
        function sortTable(n) {
            let table = document.getElementById('resultsTable');
            let switching = true;
            let dir = 'asc';
            let switchcount = 0;
            
            while (switching) {
                switching = false;
                let rows = table.rows;
                
                for (let i = 1; i < (rows.length - 1); i++) {
                    let shouldSwitch = false;
                    let x = rows[i].getElementsByTagName('TD')[n];
                    let y = rows[i + 1].getElementsByTagName('TD')[n];
                    
                    let xContent = x.innerHTML.replace(/<[^>]*>/g, '');
                    let yContent = y.innerHTML.replace(/<[^>]*>/g, '');
                    
                    xContent = isNaN(xContent) ? xContent.toLowerCase() : parseFloat(xContent.replace(/[^0-9.]/g, ''));
                    yContent = isNaN(yContent) ? yContent.toLowerCase() : parseFloat(yContent.replace(/[^0-9.]/g, ''));
                    
                    if (dir == 'asc') {
                        if (xContent > yContent) {
                            shouldSwitch = true;
                            break;
                        }
                    } else if (dir == 'desc') {
                        if (xContent < yContent) {
                            shouldSwitch = true;
                            break;
                        }
                    }
                }
                
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else {
                    if (switchcount == 0 && dir == 'asc') {
                        dir = 'desc';
                        switching = true;
                    }
                }
            }
        }
    </script>
</body>
</html>
"@
        
        $htmlContent | Out-File -FilePath $filename -Encoding UTF8
        Write-Host "[+] HTML report saved to '$filename'" -ForegroundColor Green
    }
    
    [void]SaveTextReport() {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "parameter_fuzz_$timestamp.txt"
        
        $content = @"
Parameter Fuzzing Report
Target: $($this.BaseUrl)
Parameter: $($this.ParamName)
Date: $($this.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
$('=' * 70)

"@
        
        $sortedResults = $this.FoundResults | Sort-Object { $_.Status }, { -$_.Size }
        
        foreach ($result in $sortedResults) {
            $content += @"
[$($result.Status)] $($result.ParameterValue) -> $($result.Url)
    Size: $($result.Size) bytes | Words: $($result.Words) | Time: $($result.ResponseTime)ms
    Title: $($result.Title)

"@
        }
        
        $content | Out-File -FilePath $filename -Encoding UTF8
        Write-Host "[+] Text report saved to '$filename'" -ForegroundColor Green
    }
}

# Main execution
try {
    Write-Host ""
    Write-Host "PowerShell Parameter Fuzzer" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    
    $fuzzer = [ParameterFuzzer]::new($URL, $Wordlist, $Threads, $Delay, $Method, $Parameter)
    $fuzzer.Run()
    
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}