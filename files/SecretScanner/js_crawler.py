import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import argparse
import sys
from colorama import init, Fore, Style

# Initialize colors for terminal output
init(autoreset=True)

class AdvancedReconCrawler:
    def __init__(self, start_url, max_depth=3, concurrency=15, output_file="extracted_assets.txt"):
        self.start_url = start_url
        self.base_domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.output_file = output_file
        
        # Data structures for deduplication
        self.visited_urls = set()
        self.found_assets = set()
        
        # Extensions we actively want to extract and log
        self.target_extensions = (
            '.js', '.env', '.json', '.xml', '.yml', '.yaml', 
            '.bak', '.sql', '.zip', '.tar.gz', '.config', '.php', '.txt'
        )

        # Regex to find paths inside JavaScript files and inline scripts
        self.path_regex = re.compile(
            r"""(?:"|')(((?:[a-zA-Z]{1,10}://|/)[^"']+)|\w+\.js)(?:"|')"""
        )

    def is_valid_url(self, url):
        """Ensure the URL stays within scope (same domain)."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""

    def categorize_and_store(self, url):
        """Check if URL ends with target extensions and store it."""
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        
        if any(path.endswith(ext) for ext in self.target_extensions) or '.env' in path:
            if url not in self.found_assets:
                self.found_assets.add(url)
                
                # Color code output
                if path.endswith('.js'):
                    print(f"{Fore.GREEN}[+] Found JS: {url}{Style.RESET_ALL}")
                elif '.env' in path or path.endswith('.bak') or path.endswith('.sql'):
                    print(f"{Fore.RED}[!] HIGH VALUE: {url}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[*] Found Asset: {url}{Style.RESET_ALL}")

    async def fetch(self, session, url):
        """Asynchronously fetch a URL."""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconCrawler/1.0"}
        try:
            # Disable SSL verification for targets with self-signed certs
            async with session.get(url, headers=headers, ssl=False, timeout=10) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text' in content_type or 'javascript' in content_type or 'json' in content_type:
                        return await response.text()
        except Exception:
            pass # Silently ignore timeouts and connection errors during aggressive crawling
        return None

    def extract_links(self, html, current_url):
        """Parse HTML and extract standard links and script sources."""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()

        # 1. Extract standard HTML links (a href, link href, script src)
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
            href = tag.get('href') or tag.get('src') or tag.get('action')
            if href:
                full_url = urljoin(current_url, href)
                links.add(full_url)

        # 2. Advanced: Extract hidden URLs/Endpoints using Regex from raw HTML/JS
        matches = self.path_regex.findall(html)
        for match in matches:
            extracted_path = match[0]
            # Ignore false positives like data:image
            if not extracted_path.startswith(('data:', 'javascript:', 'mailto:')):
                full_url = urljoin(current_url, extracted_path)
                links.add(full_url)

        return links

    async def worker(self, name, queue, session):
        """Worker thread to process URLs from the queue."""
        while True:
            current_url, depth = await queue.get()
            
            try:
                if depth > self.max_depth:
                    continue

                print(f"{Fore.CYAN}[Crawler-{name}] Fetching: {current_url}{Style.RESET_ALL}")
                html = await self.fetch(session, current_url)
                
                if html:
                    extracted_urls = self.extract_links(html, current_url)
                    
                    for link in extracted_urls:
                        # Clean fragments (#) from URL
                        clean_link = urlparse(link)._replace(fragment="").geturl()
                        
                        self.categorize_and_store(clean_link)
                        
                        # Only crawl further if it's in-scope and hasn't been visited
                        if self.is_valid_url(clean_link) and clean_link not in self.visited_urls:
                            self.visited_urls.add(clean_link)
                            
                            # Don't queue static assets for HTML parsing to save time
                            if not any(clean_link.lower().endswith(ext) for ext in self.target_extensions):
                                await queue.put((clean_link, depth + 1))
            
            finally:
                queue.task_done()

    async def run(self):
        """Main execution loop."""
        print(f"{Fore.MAGENTA}[*] Starting Advanced Crawl on {self.start_url}{Style.RESET_ALL}")
        self.visited_urls.add(self.start_url)
        
        queue = asyncio.Queue()
        queue.put_nowait((self.start_url, 0))

        # Use TCPConnector to limit connection pooling safely
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create workers
            workers = [
                asyncio.create_task(self.worker(i, queue, session))
                for i in range(self.concurrency)
            ]
            
            # Wait for queue to finish
            await queue.join()
            
            # Cancel workers
            for w in workers:
                w.cancel()

        self.save_results()

    def save_results(self):
        """Save discovered assets to a text file."""
        if not self.found_assets:
            print(f"{Fore.YELLOW}[!] No sensitive assets or JS files found.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.MAGENTA}[*] Crawl complete. Saving {len(self.found_assets)} assets to {self.output_file}{Style.RESET_ALL}")
        with open(self.output_file, 'w', encoding='utf-8') as f:
            for asset in sorted(self.found_assets):
                f.write(asset + '\n')
        print(f"{Fore.GREEN}[+] Successfully saved to {self.output_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Asynchronous Web Recon Crawler")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth (default: 3)")
    parser.add_argument("-c", "--concurrency", type=int, default=15, help="Number of concurrent workers (default: 15)")
    parser.add_argument("-o", "--output", default="assets.txt", help="Output text file name")
    
    args = parser.parse_args()

    # Ensure URL has scheme
    target_url = args.url
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    crawler = AdvancedReconCrawler(
        start_url=target_url, 
        max_depth=args.depth, 
        concurrency=args.concurrency,
        output_file=args.output
    )

    try:
        # Run the async event loop
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(crawler.run())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Crawl interrupted by user. Saving current progress...{Style.RESET_ALL}")
        crawler.save_results()
        sys.exit(0)