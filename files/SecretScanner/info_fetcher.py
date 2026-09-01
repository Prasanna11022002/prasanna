import re
import csv
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse

class SensitiveInfoScanner:
    def __init__(self, max_workers=10, timeout=30):
        self.max_workers = max_workers
        self.timeout = timeout
        self.results = []
        
        self.patterns = {
            'AWS_Access_Key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'AWS_Secret_Key': r'(?i)aws(.{0,20})?[\'\"][0-9a-zA-Z\/+]{40}[\'\"]',
            'AWS_Account_ID': r'(?i)aws(.{0,20})?[\'\"]?[0-9]{12}[\'\"]?',
            'RSA_Private_Key': r'-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----',
            'SSH_Private_Key': r'-----BEGIN PRIVATE KEY-----',
            'PGP_Private_Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'Generic_API_Key': r'(?i)(api[_-]?key|apikey|api[_-]?secret)[\s]*[=:]\s*[\'\"]?([a-zA-Z0-9_\-]{20,})[\'\"]?',
            'Generic_Secret': r'(?i)(secret|password|passwd|pwd)[\s]*[=:]\s*[\'\"]([^\'\"]{4,})[\'\"]',
            'Authorization_Bearer': r'(?i)authorization[\s]*:[\s]*bearer[\s]+([a-zA-Z0-9_\-\.]+)',
            'Basic_Auth': r'(?i)authorization[\s]*:[\s]*basic[\s]+([a-zA-Z0-9_\-\.=]+)',
            'JWT_Token': r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
            'Google_API_Key': r'AIza[0-9A-Za-z_\-]{35}',
            'Google_OAuth': r'ya29\.[0-9A-Za-z_\-]+',
            'GitHub_Token': r'gh[pousr]_[0-9a-zA-Z]{36,}',
            'GitHub_Old_Token': r'(?i)github[\s]*[=:][\s]*[\'\"]?([a-f0-9]{40})[\'\"]?',
            'Slack_Token': r'xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24,}',
            'Slack_Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            'Stripe_API_Key': r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
            'Square_Access_Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
            'Square_OAuth_Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
            'PayPal_Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'Email_Address': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Username_Pattern': r'(?i)(username|user|user_name|userid|user_id)[\s]*[=:]\s*[\'\"]?([a-zA-Z0-9_\-\.@]{3,})[\'\"]?',
            'Password_Plain': r'(?i)(password|passwd|pwd)[\s]*[=:]\s*[\'\"]([^\'\"]{4,})[\'\"]',
            'IPv4_Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'Database_Connection': r'(?i)(mongodb|mysql|postgresql|postgres|jdbc):\/\/[^\s]+',
            'Firebase_URL': r'https://[a-z0-9-]+\.firebaseio\.com',
            'Twilio_API_Key': r'SK[0-9a-fA-F]{32}',
            'Twilio_Account_SID': r'AC[a-zA-Z0-9_\-]{32}',
            'Mailgun_API_Key': r'key-[0-9a-zA-Z]{32}',
            'Mailchimp_API_Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'Azure_Storage_Key': r'(?i)(?:DefaultEndpointsProtocol|AccountKey)[\s]*=[\s]*[^\s;]+',
            'Heroku_API_Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'NPM_Token': r'npm_[a-zA-Z0-9]{36}',
            'Docker_Auth': r'(?i)auth[\s]*:[\s]*[\'\"]([a-zA-Z0-9+/=]{40,})[\'\"]',
            'S3_Bucket': r's3://[a-zA-Z0-9.\-]+',
            'Access_Token': r'(?i)access[_-]?token[\s]*[=:]\s*[\'\"]?([a-zA-Z0-9_\-\.]{20,})[\'\"]?',
            'Client_Secret': r'(?i)client[_-]?secret[\s]*[=:]\s*[\'\"]?([a-zA-Z0-9_\-\.]{20,})[\'\"]?',
            'Encryption_Key': r'(?i)(encryption[_-]?key|encryptionkey)[\s]*[=:]\s*[\'\"]?([a-zA-Z0-9_\-\.\/+]{16,})[\'\"]?',
            'Webhook_URL': r'https?://(?:www\.)?(?:hooks?|webhooks?)[\w\-\.\/\?=&]+',
        }

    def fetch_url_content(self, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, timeout=self.timeout, headers=headers, verify=False)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Error fetching {url}: {str(e)}")
            return ""

    def scan_content(self, content, url):
        findings = []
        for info_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                finding = {
                    'URL': url,
                    'Info_Type': info_type,
                    'Matched_Value': match.group(0)[:100],
                    'Position': match.start(),
                    'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                findings.append(finding)
        return findings

    def process_url(self, url):
        url = url.strip()
        if not url or not url.startswith(('http://', 'https://')):
            return []
        
        print(f"Scanning: {url}")
        content = self.fetch_url_content(url)
        
        if content:
            findings = self.scan_content(content, url)
            if findings:
                print(f"Found {len(findings)} potential sensitive items")
            return findings
        return []

    def scan_urls_from_file(self, input_file):
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading file: {e}")
            return

        print(f"Total URLs to scan: {len(urls)}\n")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.process_url, url): url for url in urls}
            for future in as_completed(futures):
                findings = future.result()
                self.results.extend(findings)

    def export_to_csv(self, output_file):
        if not self.results:
            print("\nNo sensitive information found!")
            return

        unique_results = []
        seen = set()
        for item in self.results:
            identifier = (item['URL'], item['Info_Type'], item['Matched_Value'])
            if identifier not in seen:
                seen.add(identifier)
                unique_results.append(item)

        unique_results.sort(key=lambda x: x['Info_Type'])

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['Info_Type', 'Matched_Value', 'URL', 'Position', 'Timestamp']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(unique_results)
            
            print(f"\nResults exported to: {output_file}")
            print(f"Total unique findings: {len(unique_results)}")
            self.print_summary(unique_results)
            
        except Exception as e:
            print(f"Error exporting to CSV: {e}")

    def print_summary(self, results):
        print("\n" + "="*60)
        print("SUMMARY OF FINDINGS")
        print("="*60)
        
        type_counts = {}
        for result in results:
            info_type = result['Info_Type']
            type_counts[info_type] = type_counts.get(info_type, 0) + 1
        
        for info_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"{info_type}: {count}")
        
        print("="*60)


def main():
    parser = argparse.ArgumentParser(description='Scan URLs for sensitive information')
    parser.add_argument('-i', '--input', required=True, help='Input file containing URLs')
    parser.add_argument('-o', '--output', default='sensitive_info_report.csv', help='Output CSV file')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='Request timeout in seconds')
    
    args = parser.parse_args()
    
    print("="*60)
    print("SENSITIVE INFORMATION SCANNER")
    print("="*60)
    print(f"Input file: {args.input}")
    print(f"Output file: {args.output}")
    print(f"Workers: {args.workers}")
    print(f"Timeout: {args.timeout}s")
    print("="*60 + "\n")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    scanner = SensitiveInfoScanner(max_workers=args.workers, timeout=args.timeout)
    scanner.scan_urls_from_file(args.input)
    scanner.export_to_csv(args.output)


if __name__ == "__main__":
    main()