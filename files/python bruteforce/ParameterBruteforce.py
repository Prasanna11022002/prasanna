import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time
import argparse
from urllib.parse import urlparse, parse_qs

class ParameterFuzzer:
    def __init__(self, url, wordlist_file, threads=10, delay=0, method='GET', param_name=None):
        self.base_url = url
        self.wordlist_file = wordlist_file
        self.threads = threads
        self.delay = delay
        self.method = method.upper()
        self.param_name = param_name
        self.found_results = []
        self.start_time = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Auto-detect parameter name from URL if not specified
        if not self.param_name:
            self.param_name = self._detect_param_name()
    
    def _detect_param_name(self):
        """Auto-detect parameter name from URL"""
        if 'FUZZ' in self.base_url.upper():
            return 'FUZZ'
        
        # Try to parse existing parameters
        parsed = urlparse(self.base_url)
        params = parse_qs(parsed.query)
        if params:
            return list(params.keys())[0]
        
        return 'id'  # Default
    
    def _build_url(self, value):
        """Build URL with fuzzed value"""
        if 'FUZZ' in self.base_url.upper():
            return self.base_url.replace('FUZZ', str(value)).replace('fuzz', str(value))
        else:
            # Handle both formats: ?id=fuzz and ?id=
            if '=' in self.base_url:
                if self.base_url.endswith('='):
                    return f"{self.base_url}{value}"
                else:
                    # Replace existing value
                    parts = self.base_url.split('=')
                    return f"{parts[0]}={value}"
            else:
                return f"{self.base_url}?{self.param_name}={value}"
    
    def test_parameter(self, word):
        """Test a single parameter value"""
        word = word.strip()
        if not word or word.startswith('#'):
            return
        
        if self.delay:
            time.sleep(self.delay)
        
        url = self._build_url(word)
        
        try:
            start = time.time()
            
            if self.method == 'GET':
                response = requests.get(url, headers=self.headers, timeout=10, allow_redirects=False)
            elif self.method == 'POST':
                # For POST, send as form data
                data = {self.param_name: word}
                response = requests.post(self.base_url.split('?')[0], data=data, headers=self.headers, timeout=10, allow_redirects=False)
            else:
                response = requests.request(self.method, url, headers=self.headers, timeout=10)
            
            response_time = (time.time() - start) * 1000
            
            status = response.status_code
            size = len(response.content)
            content_type = response.headers.get('Content-Type', 'N/A')
            
            # Check for interesting responses
            is_interesting = self._is_interesting(response, status, size)
            
            if is_interesting:
                color = self.get_color(status)
                print(f"{color}[{status}] Size: {size:7d} | {word} -> {url[:80]}{self.reset_color()}")
                
                result = {
                    'parameter_value': word,
                    'url': url,
                    'status': status,
                    'size': size,
                    'content_type': content_type,
                    'response_time': round(response_time, 2),
                    'redirect': response.headers.get('Location', ''),
                    'server': response.headers.get('Server', 'N/A'),
                    'title': self._extract_title(response.text),
                    'words': len(response.text.split()),
                    'lines': response.text.count('\n')
                }
                
                self.found_results.append(result)
                
        except requests.exceptions.Timeout:
            print(f"[!] Timeout: {word}")
        except requests.exceptions.RequestException as e:
            pass
    
    def _is_interesting(self, response, status, size):
        """Determine if response is interesting"""
        # Common status codes to report
        if status in [200, 201, 204, 301, 302, 307, 308, 401, 403, 500, 502, 503]:
            return True
        
        # Large responses might be interesting
        if size > 1000:
            return True
        
        return False
    
    def _extract_title(self, html):
        """Extract title from HTML"""
        try:
            import re
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()[:100]
        except:
            pass
        return 'N/A'
    
    def get_color(self, status):
        """Color code based on status"""
        if status == 200:
            return '\033[92m'  # Green
        elif status in [301, 302, 307, 308]:
            return '\033[93m'  # Yellow
        elif status in [401, 403]:
            return '\033[94m'  # Blue
        elif status >= 500:
            return '\033[91m'  # Red
        return ''
    
    def reset_color(self):
        return '\033[0m'
    
    def run(self):
        """Run the fuzzer"""
        try:
            with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            
            print(f"\n{'='*70}")
            print(f"[*] Target: {self.base_url}")
            print(f"[*] Parameter: {self.param_name}")
            print(f"[*] Wordlist: {self.wordlist_file} ({len(words)} values)")
            print(f"[*] Threads: {self.threads}")
            print(f"[*] Method: {self.method}")
            print(f"{'='*70}\n")
            
            self.start_time = datetime.now()
            start = time.time()
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.test_parameter, words)
            
            elapsed = time.time() - start
            
            print(f"\n{'='*70}")
            print(f"[*] Finished in {elapsed:.2f} seconds")
            print(f"[*] Found {len(self.found_results)} interesting responses")
            print(f"{'='*70}\n")
            
            self.save_html_report(elapsed, len(words))
            self.save_text_report()
            
        except FileNotFoundError:
            print(f"[ERROR] Wordlist '{self.wordlist_file}' not found!")
        except KeyboardInterrupt:
            print("\n[!] Stopped by user")
            elapsed = time.time() - start if 'start' in locals() else 0
            self.save_html_report(elapsed, len(words) if 'words' in locals() else 0)
    
    def save_html_report(self, elapsed_time, total_words):
        """Generate HTML report"""
        filename = f"parameter_fuzz_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        sorted_results = sorted(self.found_results, key=lambda x: (x['status'], -x['size']))
        
        # Statistics
        status_counts = {}
        for result in self.found_results:
            status = str(result['status'])
            status_counts[status] = status_counts.get(status, 0) + 1
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Parameter Fuzzing Report - {self.param_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .url {{
            font-size: 1.2em;
            opacity: 0.9;
            margin: 10px 0;
            word-break: break-all;
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 5px;
        }}
        
        .header .param {{
            font-size: 1em;
            opacity: 0.8;
            margin-top: 10px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .stat-card h3 {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }}
        
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .filters {{
            padding: 20px 30px;
            background: white;
            border-bottom: 2px solid #f0f0f0;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .filters input {{
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
            flex: 1;
            min-width: 200px;
        }}
        
        .filters select {{
            padding: 10px 15px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
            cursor: pointer;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        thead {{
            background: #f8f9fa;
            position: sticky;
            top: 0;
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #555;
            border-bottom: 2px solid #ddd;
            cursor: pointer;
            user-select: none;
        }}
        
        th:hover {{
            background: #e9ecef;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #f0f0f0;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .status-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            display: inline-block;
            min-width: 60px;
            text-align: center;
        }}
        
        .status-200 {{ background: #d4edda; color: #155724; }}
        .status-201 {{ background: #d4edda; color: #155724; }}
        .status-204 {{ background: #d4edda; color: #155724; }}
        .status-301 {{ background: #fff3cd; color: #856404; }}
        .status-302 {{ background: #fff3cd; color: #856404; }}
        .status-307 {{ background: #fff3cd; color: #856404; }}
        .status-308 {{ background: #fff3cd; color: #856404; }}
        .status-401 {{ background: #cce5ff; color: #004085; }}
        .status-403 {{ background: #cce5ff; color: #004085; }}
        .status-405 {{ background: #e2e3e5; color: #383d41; }}
        .status-500 {{ background: #f8d7da; color: #721c24; }}
        .status-502 {{ background: #f8d7da; color: #721c24; }}
        .status-503 {{ background: #f8d7da; color: #721c24; }}
        
        .url-link {{
            color: #667eea;
            text-decoration: none;
            word-break: break-all;
        }}
        
        .url-link:hover {{
            text-decoration: underline;
        }}
        
        .param-value {{
            font-family: monospace;
            background: #f8f9fa;
            padding: 3px 8px;
            border-radius: 3px;
            color: #e83e8c;
            font-weight: bold;
        }}
        
        .size {{
            color: #666;
            font-family: monospace;
        }}
        
        .response-time {{
            color: #666;
            font-size: 0.9em;
        }}
        
        .footer {{
            padding: 20px;
            text-align: center;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Parameter Fuzzing Report</h1>
            <div class="url">{self.base_url}</div>
            <div class="param">Fuzzing Parameter: <strong>{self.param_name}</strong></div>
            <p style="font-size: 0.9em; margin-top: 10px;">
                Scan Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Interesting Results</h3>
                <div class="value">{len(self.found_results)}</div>
            </div>
            <div class="stat-card">
                <h3>Total Values Tested</h3>
                <div class="value">{total_words}</div>
            </div>
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <div class="value">{elapsed_time:.2f}s</div>
            </div>
            <div class="stat-card">
                <h3>Hit Rate</h3>
                <div class="value">{(len(self.found_results)/total_words*100) if total_words > 0 else 0:.1f}%</div>
            </div>
        </div>
        
        <div class="filters">
            <input type="text" id="searchInput" placeholder="🔍 Search parameter values..." onkeyup="filterTable()">
            <select id="statusFilter" onchange="filterTable()">
                <option value="">All Status Codes</option>
                {self._generate_status_options(status_counts)}
            </select>
            <select id="sizeFilter" onchange="filterTable()">
                <option value="">All Sizes</option>
                <option value="large">Large (>10KB)</option>
                <option value="medium">Medium (1KB-10KB)</option>
                <option value="small">Small (<1KB)</option>
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
                    {self._generate_table_rows(sorted_results)}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by Parameter Fuzzer | Method: {self.method} | Threads: {self.threads}</p>
        </div>
    </div>
    
    <script>
        function filterTable() {{
            let searchInput = document.getElementById('searchInput').value.toLowerCase();
            let statusFilter = document.getElementById('statusFilter').value;
            let sizeFilter = document.getElementById('sizeFilter').value;
            let table = document.getElementById('resultsTable');
            let tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {{
                let td = tr[i].getElementsByTagName('td');
                let paramValue = td[2].textContent.toLowerCase();
                let status = td[1].textContent.trim();
                let size = parseInt(td[3].textContent.replace(/[^0-9]/g, ''));
                
                let matchSearch = paramValue.includes(searchInput);
                let matchStatus = statusFilter === '' || status === statusFilter;
                let matchSize = true;
                
                if (sizeFilter === 'large') matchSize = size > 10240;
                else if (sizeFilter === 'medium') matchSize = size >= 1024 && size <= 10240;
                else if (sizeFilter === 'small') matchSize = size < 1024;
                
                if (matchSearch && matchStatus && matchSize) {{
                    tr[i].style.display = '';
                }} else {{
                    tr[i].style.display = 'none';
                }}
            }}
        }}
        
        function sortTable(n) {{
            let table = document.getElementById('resultsTable');
            let switching = true;
            let dir = 'asc';
            let switchcount = 0;
            
            while (switching) {{
                switching = false;
                let rows = table.rows;
                
                for (let i = 1; i < (rows.length - 1); i++) {{
                    let shouldSwitch = false;
                    let x = rows[i].getElementsByTagName('TD')[n];
                    let y = rows[i + 1].getElementsByTagName('TD')[n];
                    
                    let xContent = x.innerHTML.replace(/<[^>]*>/g, '');
                    let yContent = y.innerHTML.replace(/<[^>]*>/g, '');
                    
                    xContent = isNaN(xContent) ? xContent.toLowerCase() : parseFloat(xContent.replace(/[^0-9.]/g, ''));
                    yContent = isNaN(yContent) ? yContent.toLowerCase() : parseFloat(yContent.replace(/[^0-9.]/g, ''));
                    
                    if (dir == 'asc') {{
                        if (xContent > yContent) {{
                            shouldSwitch = true;
                            break;
                        }}
                    }} else if (dir == 'desc') {{
                        if (xContent < yContent) {{
                            shouldSwitch = true;
                            break;
                        }}
                    }}
                }}
                
                if (shouldSwitch) {{
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                }} else {{
                    if (switchcount == 0 && dir == 'asc') {{
                        dir = 'desc';
                        switching = true;
                    }}
                }}
            }}
        }}
    </script>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved to '{filename}'")
    
    def _generate_status_options(self, status_counts):
        """Generate filter options"""
        options = ""
        for status in sorted(status_counts.keys()):
            options += f'<option value="{status}">{status} ({status_counts[status]})</option>\n'
        return options
    
    def _generate_table_rows(self, results):
        """Generate table rows"""
        if not results:
            return '<tr><td colspan="9" style="text-align: center; padding: 50px; color: #999;">No interesting results found</td></tr>'
        
        rows = ""
        for idx, result in enumerate(results, 1):
            status = str(result['status'])
            redirect_info = f" → {result['redirect'][:30]}..." if result['redirect'] else ""
            
            rows += f"""
            <tr>
                <td>{idx}</td>
                <td><span class="status-badge status-{status}">{status}</span></td>
                <td><span class="param-value">{result['parameter_value']}</span></td>
                <td class="size">{result['size']:,} bytes</td>
                <td>{result['words']}</td>
                <td>{result['lines']}</td>
                <td class="response-time">{result['response_time']} ms</td>
                <td>{result['title'][:50]}</td>
                <td><a href="{result['url']}" target="_blank" class="url-link">{result['url'][:60]}...</a>{redirect_info}</td>
            </tr>
            """
        return rows
    
    def save_text_report(self):
        """Save simple text report"""
        filename = f"parameter_fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(f"Parameter Fuzzing Report\n")
            f.write(f"Target: {self.base_url}\n")
            f.write(f"Parameter: {self.param_name}\n")
            f.write(f"Date: {self.start_time}\n")
            f.write(f"{'='*70}\n\n")
            
            for result in sorted(self.found_results, key=lambda x: (x['status'], -x['size'])):
                f.write(f"[{result['status']}] {result['parameter_value']} -> {result['url']}\n")
                f.write(f"    Size: {result['size']} bytes | Words: {result['words']} | Time: {result['response_time']}ms\n")
                if result['title'] != 'N/A':
                    f.write(f"    Title: {result['title']}\n")
                f.write("\n")
        
        print(f"[+] Text report saved to '{filename}'")

# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Parameter Fuzzer with HTML Report',
        epilog='Examples:\n'
               '  python fuzzer.py -u "https://example.com/page?id=FUZZ" -w wordlist.txt\n'
               '  python fuzzer.py -u "https://example.com/api?user=" -w users.txt -p user\n'
               '  python fuzzer.py -u "https://example.com" -w ids.txt -p id -m POST',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL (use FUZZ as placeholder or specify with -p)')
    parser.add_argument('-w', '--wordlist', required=True, 
                       help='Wordlist file')
    parser.add_argument('-p', '--param', 
                       help='Parameter name (auto-detected if FUZZ in URL)')
    parser.add_argument('-t', '--threads', type=int, default=10, 
                       help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0, 
                       help='Delay between requests in seconds')
    parser.add_argument('-m', '--method', default='GET', 
                       help='HTTP method (default: GET)')
    
    args = parser.parse_args()
    
    fuzzer = ParameterFuzzer(
        url=args.url,
        wordlist_file=args.wordlist,
        threads=args.threads,
        delay=args.delay,
        method=args.method,
        param_name=args.param
    )
    
    fuzzer.run()