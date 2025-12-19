#!/usr/bin/env python3
"""
CJChecker - ClickJacking Security Checker
A tiny tool to detect missing anti-ClickJacking headers in web applications
"""

import argparse
import sys
import requests
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import urllib.parse

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def print_banner():
    """Display the tool banner"""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════╗
║          CJChecker - ClickJacking Checker        ║
║          Security Header Analysis Tool           ║
║                By URDev - v1.0                   ║
╚══════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)

def check_clickjacking_headers(headers: Dict) -> Tuple[bool, Dict, List[str]]:
    """
    Check response headers for ClickJacking protection mechanisms
    
    Returns:
        Tuple: (is_secure, header_status, recommendations)
    """
    security_headers = {
        'X-Frame-Options': {
            'present': False,
            'value': None,
            'secure': False
        },
        'Content-Security-Policy': {
            'present': False,
            'value': None,
            'secure': False,
            'frame_ancestors': False
        },
        'Frame-Options': {
            'present': False,
            'value': None,
            'secure': False
        }
    }
    
    recommendations = []
    
    # Check each header
    for header_name, header_value in headers.items():
        header_lower = header_name.lower()
        
        # X-Frame-Options
        if header_lower == 'x-frame-options':
            security_headers['X-Frame-Options']['present'] = True
            security_headers['X-Frame-Options']['value'] = header_value
            
            if header_value.upper() in ['DENY', 'SAMEORIGIN']:
                security_headers['X-Frame-Options']['secure'] = True
            else:
                recommendations.append(f"X-Frame-Options has weak value: {header_value}")
        
        # Content-Security-Policy
        elif header_lower == 'content-security-policy':
            security_headers['Content-Security-Policy']['present'] = True
            security_headers['Content-Security-Policy']['value'] = header_value
            
            # Check for frame-ancestors directive
            if 'frame-ancestors' in header_value.lower():
                security_headers['Content-Security-Policy']['frame_ancestors'] = True
                
                # Check if frame-ancestors is properly configured
                if "'none'" in header_value.lower() or "'self'" in header_value.lower():
                    security_headers['Content-Security-Policy']['secure'] = True
                elif 'http' in header_value.lower():
                    recommendations.append("CSP frame-ancestors allows external domains")
            else:
                recommendations.append("CSP present but missing frame-ancestors directive")
        
        # Frame-Options (deprecated but sometimes -weirdly- used)
        elif header_lower == 'frame-options':
            security_headers['Frame-Options']['present'] = True
            security_headers['Frame-Options']['value'] = header_value
            recommendations.append("Frame-Options is deprecated, use X-Frame-Options or CSP instead")
    
    # Determine overall security status
    is_secure = any([
        security_headers['X-Frame-Options']['secure'],
        security_headers['Content-Security-Policy']['secure']
    ])
    
    # If no headers found, add recommendations
    if not (security_headers['X-Frame-Options']['present'] or 
            security_headers['Content-Security-Policy']['present']):
        recommendations = [
            "No ClickJacking protection headers found!",
            "Add X-Frame-Options: DENY or SAMEORIGIN",
            "Add Content-Security-Policy with frame-ancestors 'none' or 'self'"
        ]
    
    return is_secure, security_headers, recommendations

def analyze_url(url: str, timeout: int = 10) -> Dict:
    """
    Analyze a single URL for ClickJacking vulnerabilities
    
    Returns:
        Dictionary with analysis results
    """
    result = {
        'url': url,
        'success': False,
        'error': None,
        'secure': False,
        'headers': {},
        'security_headers': {},
        'recommendations': [],
        'status_code': None,
        'response_time': None
    }
    
    try:
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Send HTTP request
        start_time = datetime.now()
        response = requests.get(
            url, 
            timeout=timeout,
            headers={
                'User-Agent': 'CJChecker/1.0 Security Scanner'
            },
            allow_redirects=True
        )
        response_time = (datetime.now() - start_time).total_seconds()
        
        result['status_code'] = response.status_code
        result['response_time'] = response_time
        result['headers'] = dict(response.headers)
        
        # Check ClickJacking headers
        is_secure, security_headers, recommendations = check_clickjacking_headers(response.headers)
        
        result['secure'] = is_secure
        result['security_headers'] = security_headers
        result['recommendations'] = recommendations
        result['success'] = True
        
    except requests.exceptions.Timeout:
        result['error'] = f"Request timeout ({timeout}s)"
    except requests.exceptions.SSLError:
        result['error'] = "SSL/TLS error"
    except requests.exceptions.ConnectionError:
        result['error'] = "Connection failed"
    except requests.exceptions.TooManyRedirects:
        result['error'] = "Too many redirects"
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"
    
    return result

def print_single_result(result: Dict):
    """Print analysis result for a single URL"""
    print(f"\n{Colors.BOLD}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}URL:{Colors.RESET} {Colors.CYAN}{result['url']}{Colors.RESET}")
    
    if not result['success']:
        print(f"{Colors.RED}✗ Error: {result['error']}{Colors.RESET}")
        return
    
    # Status and response info
    status_color = Colors.GREEN if 200 <= result['status_code'] < 300 else Colors.YELLOW
    print(f"{Colors.BOLD}Status:{Colors.RESET} {status_color}{result['status_code']}{Colors.RESET} | "
          f"{Colors.BOLD}Time:{Colors.RESET} {result['response_time']:.2f}s")
    
    # Security status
    if result['secure']:
        print(f"{Colors.BOLD}Security:{Colors.RESET} {Colors.GREEN}✓ PROTECTED{Colors.RESET}")
    else:
        print(f"{Colors.BOLD}Security:{Colors.RESET} {Colors.RED}✗ VULNERABLE{Colors.RESET}")
    
    # Headers found
    print(f"\n{Colors.BOLD}Security Headers Found:{Colors.RESET}")
    
    headers_found = False
    for header_name, header_info in result['security_headers'].items():
        if header_info['present']:
            headers_found = True
            status_icon = f"{Colors.GREEN}✓" if header_info.get('secure', False) else f"{Colors.YELLOW}⚠"
            print(f"  {status_icon}{Colors.RESET} {header_name}: {header_info['value']}")
    
    if not headers_found:
        print(f"  {Colors.RED}✗ No security headers found{Colors.RESET}")
    
    # Recommendations
    if result['recommendations']:
        print(f"\n{Colors.BOLD}Recommendations:{Colors.RESET}")
        for rec in result['recommendations']:
            if '!' in rec or 'missing' in rec.lower() or 'no' in rec.lower():
                print(f"  {Colors.RED}⚠ {rec}{Colors.RESET}")
            elif 'weak' in rec.lower() or 'deprecated' in rec.lower():
                print(f"  {Colors.YELLOW}⚠ {rec}{Colors.RESET}")
            else:
                print(f"  {Colors.BLUE}ℹ {rec}{Colors.RESET}")
    
    print(f"{Colors.BOLD}{'═' * 70}{Colors.RESET}")

def print_summary(results: List[Dict]):
    """Print summary of all analyzed URLs"""
    print(f"\n{Colors.BOLD}{'═' * 22}{Colors.RESET}")
    print(f"{Colors.BOLD}SUMMARY REPORT{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * 22}{Colors.RESET}")
    
    total = len(results)
    successful = sum(1 for r in results if r['success'])
    secure = sum(1 for r in results if r.get('secure', False))
    vulnerable = successful - secure
    
    print(f"{Colors.BOLD}Total URLs:{Colors.RESET} {total}")
    print(f"{Colors.BOLD}Successfully checked:{Colors.RESET} {successful}")
    print(f"{Colors.BOLD}Protected:{Colors.RESET} {Colors.GREEN}{secure}{Colors.RESET}")
    print(f"{Colors.BOLD}Vulnerable:{Colors.RESET} {Colors.RED}{vulnerable}{Colors.RESET}")
    
    if total > 0:
        protection_rate = (secure / successful * 100) if successful > 0 else 0
        print(f"{Colors.BOLD}Protection Rate:{Colors.RESET} {protection_rate:.1f}%")
    
    # List vulnerable URLs
    vulnerable_urls = [r for r in results if r['success'] and not r['secure']]
    if vulnerable_urls:
        print(f"\n{Colors.BOLD}Vulnerable URLs:{Colors.RESET}")
        for result in vulnerable_urls:
            print(f"  {Colors.RED}✗{Colors.RESET} {result['url']}")

def read_urls_from_file(file_path: str) -> List[str]:
    """Read URLs from a file"""
    urls = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):  # Skip empty lines and comments
                    urls.append(url)
    except Exception as e:
        print(f"{Colors.RED}Error reading file: {str(e)}{Colors.RESET}")
        sys.exit(1)
    return urls

def main():
    parser = argparse.ArgumentParser(
        description='CJChecker - ClickJacking Security Header Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Colors.BOLD}Examples:{Colors.RESET}
  %(prog)s -u https://example.com
  %(prog)s -l urls.txt
  %(prog)s -u https://example.com -t 5
  %(prog)s -l urls.txt -w 10"""
    )
    
    # Arguments (flags)
    parser.add_argument('-u', '--url', 
                       help='Single URL to check')
    parser.add_argument('-l', '--list', 
                       help='File containing list of URLs to check')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-w', '--workers', type=int, default=5,
                       help='Number of concurrent workers for list mode (default: 5)')
    parser.add_argument('-o', '--output', 
                       help='Output file for results (optional)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url and not args.list:
        parser.print_help()
        print(f"\n{Colors.RED}Error: You must specify either -u/--url or -l/--list{Colors.RESET}")
        sys.exit(1)
    
    if args.url and args.list:
        print(f"{Colors.YELLOW}Warning: Both -u and -l specified. Using list mode.{Colors.RESET}")
    
    # Display EPIC banner
    print_banner()
    
    # Collect URLs to check
    urls_to_check = []
    
    if args.list:
        urls_to_check = read_urls_from_file(args.list)
        print(f"{Colors.BLUE}[*] Loaded {len(urls_to_check)} URLs from {args.list}{Colors.RESET}")
    elif args.url:
        urls_to_check = [args.url]
    
    if not urls_to_check:
        print(f"{Colors.RED}No URLs to check{Colors.RESET}")
        sys.exit(1)
    
    # Analyze URLs
    results = []
    
    if len(urls_to_check) == 1:
        # Single URL mode
        print(f"{Colors.BLUE}[*] Analyzing single URL...{Colors.RESET}")
        result = analyze_url(urls_to_check[0], args.timeout)
        results.append(result)
        print_single_result(result)
    else:
        # List mode with concurrency
        print(f"{Colors.BLUE}[*] Analyzing {len(urls_to_check)} URLs with {args.workers} workers...{Colors.RESET}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            # Submit all URLs for analysis
            future_to_url = {
                executor.submit(analyze_url, url, args.timeout): url 
                for url in urls_to_check
            }
            
            # Process results as they complete
            for i, future in enumerate(concurrent.futures.as_completed(future_to_url), 1):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Progress indicator
                    progress = f"[{i}/{len(urls_to_check)}]"
                    if result['success']:
                        if result['secure']:
                            status = f"{Colors.GREEN}✓{Colors.RESET}"
                        else:
                            status = f"{Colors.RED}✗{Colors.RESET}"
                    else:
                        status = f"{Colors.YELLOW}?{Colors.RESET}"
                    
                    print(f"{progress} {status} {url}")
                    
                except Exception as e:
                    print(f"{Colors.RED}Error analyzing {url}: {str(e)}{Colors.RESET}")
    
    # Print summary
    if len(urls_to_check) > 1:
        print_summary(results)
    
    # Save results to file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                for result in results:
                    f.write(f"URL: {result['url']}\n")
                    if result['success']:
                        f.write(f"Status: {result.get('status_code', 'N/A')}\n")
                        f.write(f"Protected: {result.get('secure', False)}\n")
                        f.write(f"Headers: {result.get('security_headers', {})}\n")
                        f.write(f"Recommendations: {', '.join(result.get('recommendations', []))}\n")
                    else:
                        f.write(f"Error: {result.get('error', 'Unknown')}\n")
                    f.write("-" * 50 + "\n")
            print(f"{Colors.GREEN}[*] Results saved to {args.output}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error saving results: {str(e)}{Colors.RESET}")
    
    # Exit with appropriate code
    vulnerable_count = sum(1 for r in results if r['success'] and not r['secure'])
    if vulnerable_count > 0:
        print(f"\n{Colors.YELLOW}[!] Found {vulnerable_count} vulnerable URLs{Colors.RESET}")
        sys.exit(1)
    else:
        print(f"\n{Colors.GREEN}[✓] All checked URLs are protected against ClickJacking{Colors.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(130)
