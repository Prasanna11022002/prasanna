import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time
import json
import argparse

class EndpointTesterHTML:
    def __init__(self, base_url, wordlist_file, threads=10, delay=0, extensions=None, method='GET'):
        self.base_url = base_url.rstrip('/')
        self.wordlist_file = wordlist_file
        self.threads = threads
        self.delay = delay
        self.extensions = extensions or ['']
        self.method = method.upper()
        self.found_endpoints = []
        self.start_time = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def test_endpoint(self, word):
        """Test endpoint with extensions"""
        word = word.strip().lstrip('/')
        if not word or word.startswith('#'):
            return
        
        for ext in self.extensions:
            if self.delay:
                time.sleep(self.delay)
            
            endpoint = f"{word}{ext}"
            url = f"{self.base_url}/{endpoint}"
            
            try:
                start = time.time()
                
                if self.method == 'GET':
                    response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                elif self.method == 'POST':
                    response = requests.post(url, headers=self.headers, timeout=5, allow_redirects=False)
                else:
                    response = requests.request(self.method, url, headers=self.headers, timeout=5)
                
                response_time = (time.time() - start) * 1000  # Convert to ms
                
                status = response.status_code
                size = len(response.content)
                content_type = response.headers.get('Content-Type', 'N/A')
                
                # Status codes to report
                if status in [200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503]:
                    color = self.get_color(status)
                    print(f"{color}[{status}] Size: {size:7d} | {endpoint}{self.reset_color()}")
                    
                    self.found_endpoints.append({
                        'endpoint': endpoint,
                        'url': url,
                        'status': status,
                        'size': size,
                        'content_type': content_type,
                        'response_time': round(response_time, 2),
                        'redirect': response.headers.get('Location', ''),
                        'server': response.headers.get('Server', 'N/A')
                    })
                    
            except requests.exceptions.Timeout:
                self.found_endpoints.append({
                    'endpoint': endpoint,
                    'url': url,
                    'status': 'TIMEOUT',
                    'size': 0,
                    'content_type': 'N/A',
                    'response_time': 5000,
                    'redirect': '',
                    'server': 'N/A'
                })
            except requests.exceptions.RequestException as e:
                pass
    
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
            
            print(f"\n{'='*60}")
            print(f"[*] Target: {self.base_url}")
            print(f"[*] Wordlist: {self.wordlist_file} ({len(words)} words)")
            print(f"[*] Threads: {self.threads}")
            print(f"[*] Method: {self.method}")
            if self.extensions:
                print(f"[*] Extensions: {', '.join(self.extensions)}")
            print(f"{'='*60}\n")
            
            self.start_time = datetime.now()
            start = time.time()
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.test_endpoint, words)
            
            elapsed = time.time() - start
            
            print(f"\n{'='*60}")
            print(f"[*] Finished in {elapsed:.2f} seconds")
            print(f"[*] Found {len(self.found_endpoints)} endpoints")
            print(f"{'='*60}\n")
            
            self.save_html_report(elapsed, len(words))
            self.save_text_report()
            
        except FileNotFoundError:
            print(f"[ERROR] Wordlist '{self.wordlist_file}' not found!")
        except KeyboardInterrupt:
            print("\n[!] Stopped by user")
            elapsed = time.time() - start if 'start' in locals() else 0
            self.save_html_report(elapsed, len(words) if 'words' in locals() else 0)
    
    def save_html_report(self, elapsed_time, total_words):
        """Generate beautiful HTML report"""
        filename = f"endpoint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Sort endpoints by status code
        sorted_endpoints = sorted(self.found_endpoints, key=lambda x: (str(x['status']), x['endpoint']))
        
        # Statistics
        status_counts = {}
        for endpoint in self.found_endpoints:
            status = str(endpoint['status'])
            status_counts[status] = status_counts.get(status, 0) + 1
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Endpoint Fuzzing Report - {self.base_url}</title>
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
            max-width: 1400px;
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
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
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
        
        .status-legend {{
            padding: 20px 30px;
            background: #f8f9fa;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 3px;
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
        .status-TIMEOUT {{ background: #f8d7da; color: #721c24; }}
        
        .url-link {{
            color: #667eea;
            text-decoration: none;
            word-break: break-all;
        }}
        
        .url-link:hover {{
            text-decoration: underline;
        }}
        
        .no-results {{
            text-align: center;
            padding: 50px;
            color: #999;
            font-size: 1.2em;
        }}
        
        .footer {{
            padding: 20px;
            text-align: center;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }}
        
        .size {{
            color: #666;
            font-family: monospace;
        }}
        
        .response-time {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Endpoint Fuzzing Report</h1>
            <p>{self.base_url}</p>
            <p style="font-size: 0.9em; margin-top: 10px;">
                Scan Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Endpoints Found</h3>
                <div class="value">{len(self.found_endpoints)}</div>
            </div>
            <div class="stat-card">
                <h3>Total Words Tested</h3>
                <div class="value">{total_words}</div>
            </div>
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <div class="value">{elapsed_time:.2f}s</div>
            </div>
            <div class="stat-card">
                <h3>Success Rate</h3>
                <div class="value">{(len(self.found_endpoints)/total_words*100) if total_words > 0 else 0:.1f}%</div>
            </div>
        </div>
        
        <div class="status-legend">
            <h3 style="width: 100%; margin-bottom: 10px;">Status Code Distribution:</h3>
            {self._generate_status_legend(status_counts)}
        </div>
        
        <div class="filters">
            <input type="text" id="searchInput" placeholder="🔍 Search endpoints..." onkeyup="filterTable()">
            <select id="statusFilter" onchange="filterTable()">
                <option value="">All Status Codes</option>
                {self._generate_status_options(status_counts)}
            </select>
        </div>
        
        <div style="overflow-x: auto;">
            <table id="endpointTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">#</th>
                        <th onclick="sortTable(1)">Status ▼</th>
                        <th onclick="sortTable(2)">Endpoint</th>
                        <th onclick="sortTable(3)">Size</th>
                        <th onclick="sortTable(4)">Response Time</th>
                        <th onclick="sortTable(5)">Content-Type</th>
                        <th onclick="sortTable(6)">Server</th>
                        <th onclick="sortTable(7)">Redirect</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_table_rows(sorted_endpoints)}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by Endpoint Fuzzer | Method: {self.method} | Threads: {self.threads}</p>
        </div>
    </div>
    
    <script>
        function filterTable() {{
            let searchInput = document.getElementById('searchInput').value.toLowerCase();
            let statusFilter = document.getElementById('statusFilter').value;
            let table = document.getElementById('endpointTable');
            let tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {{
                let td = tr[i].getElementsByTagName('td');
                let endpoint = td[2].textContent.toLowerCase();
                let status = td[1].textContent.trim();
                
                let matchSearch = endpoint.includes(searchInput);
                let matchStatus = statusFilter === '' || status === statusFilter;
                
                if (matchSearch && matchStatus) {{
                    tr[i].style.display = '';
                }} else {{
                    tr[i].style.display = 'none';
                }}
            }}
        }}
        
        function sortTable(n) {{
            let table = document.getElementById('endpointTable');
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
                    
                    let xContent = isNaN(x.innerHTML) ? x.innerHTML.toLowerCase() : parseFloat(x.innerHTML);
                    let yContent = isNaN(y.innerHTML) ? y.innerHTML.toLowerCase() : parseFloat(y.innerHTML);
                    
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
    
    def _generate_status_legend(self, status_counts):
        """Generate status code legend"""
        colors = {
            '200': '#d4edda', '201': '#d4edda', '204': '#d4edda',
            '301': '#fff3cd', '302': '#fff3cd', '307': '#fff3cd', '308': '#fff3cd',
            '401': '#cce5ff', '403': '#cce5ff', '405': '#e2e3e5',
            '500': '#f8d7da', '502': '#f8d7da', '503': '#f8d7da',
            'TIMEOUT': '#f8d7da'
        }
        
        legend_html = ""
        for status, count in sorted(status_counts.items()):
            color = colors.get(status, '#e2e3e5')
            legend_html += f"""
            <div class="legend-item">
                <div class="legend-color" style="background: {color};"></div>
                <span><strong>{status}</strong>: {count}</span>
            </div>
            """
        return legend_html
    
    def _generate_status_options(self, status_counts):
        """Generate filter options"""
        options = ""
        for status in sorted(status_counts.keys()):
            options += f'<option value="{status}">{status} ({status_counts[status]})</option>\n'
        return options
    
    def _generate_table_rows(self, endpoints):
        """Generate table rows"""
        if not endpoints:
            return '<tr><td colspan="8" class="no-results">No endpoints found</td></tr>'
        
        rows = ""
        for idx, endpoint in enumerate(endpoints, 1):
            status = str(endpoint['status'])
            redirect_cell = f'<a href="{endpoint["redirect"]}" target="_blank" class="url-link">{endpoint["redirect"][:50]}...</a>' if endpoint['redirect'] else '-'
            
            rows += f"""
            <tr>
                <td>{idx}</td>
                <td><span class="status-badge status-{status}">{status}</span></td>
                <td><a href="{endpoint['url']}" target="_blank" class="url-link">{endpoint['endpoint']}</a></td>
                <td class="size">{endpoint['size']:,} bytes</td>
                <td class="response-time">{endpoint['response_time']} ms</td>
                <td>{endpoint['content_type'][:30]}</td>
                <td>{endpoint['server']}</td>
                <td>{redirect_cell}</td>
            </tr>
            """
        return rows
    
    def save_text_report(self):
        """Save simple text report as well"""
        filename = f"endpoints_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(f"Endpoint Fuzzing Report\n")
            f.write(f"Target: {self.base_url}\n")
            f.write(f"Date: {self.start_time}\n")
            f.write(f"{'='*60}\n\n")
            
            for endpoint in sorted(self.found_endpoints, key=lambda x: (str(x['status']), x['endpoint'])):
                f.write(f"[{endpoint['status']}] {endpoint['url']} ({endpoint['size']} bytes)\n")
        
        print(f"[+] Text report saved to '{filename}'")

# Command line version
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Web Endpoint Fuzzer with HTML Report')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests in seconds')
    parser.add_argument('-e', '--extensions', help='Extensions to test (comma separated, e.g., php,html,txt)')
    parser.add_argument('-m', '--method', default='GET', help='HTTP method (default: GET)')
    
    args = parser.parse_args()
    
    extensions = ['']
    if args.extensions:
        extensions = [''] + ['.' + ext.lstrip('.') for ext in args.extensions.split(',')]
    
    tester = EndpointTesterHTML(
        base_url=args.url,
        wordlist_file=args.wordlist,
        threads=args.threads,
        delay=args.delay,
        extensions=extensions,
        method=args.method
    )
    
    tester.run()