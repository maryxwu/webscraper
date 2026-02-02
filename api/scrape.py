"""
Vercel Serverless Function - Website Scraper API
"""

import csv
import re
import io
import json
from urllib.parse import urljoin, urlparse
from http.server import BaseHTTPRequestHandler
import urllib.request
import urllib.error
import ssl


# Regex patterns
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)
CF_EMAIL_PATTERN = re.compile(r'data-cfemail="([a-fA-F0-9]+)"')
CF_EMAIL_HREF_PATTERN = re.compile(r'/cdn-cgi/l/email-protection#([a-fA-F0-9]+)')

US_STATES = {
    'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
    'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
    'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
    'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
    'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY',
    'DC', 'PR'
}
ZIP_PATTERN = re.compile(r'\b\d{5}(?:-\d{4})?\b')
STREET_PATTERN = re.compile(
    r'\b\d+\s+[\w\s]+(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln|way|court|ct|place|pl|circle|cir)\b',
    re.IGNORECASE
)


def decode_cloudflare_email(encoded_string):
    """Decode Cloudflare's email protection encoding."""
    try:
        key = int(encoded_string[:2], 16)
        decoded = ''
        for i in range(2, len(encoded_string), 2):
            char_code = int(encoded_string[i:i+2], 16) ^ key
            decoded += chr(char_code)
        return decoded
    except (ValueError, IndexError):
        return None


def normalize_url(url):
    """Ensure URL has a scheme."""
    url = url.strip()
    if not url:
        return None
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def fetch_page(url, timeout=8):
    """Fetch a webpage and return its content."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None


def extract_emails(html_content):
    """Extract email addresses from page content."""
    emails = set()
    if not html_content:
        return list(emails)

    # Find plain emails
    found = EMAIL_PATTERN.findall(html_content)
    emails.update(found)

    # Find Cloudflare-protected emails
    for encoded in CF_EMAIL_PATTERN.findall(html_content):
        decoded = decode_cloudflare_email(encoded)
        if decoded and EMAIL_PATTERN.match(decoded):
            emails.add(decoded)

    for encoded in CF_EMAIL_HREF_PATTERN.findall(html_content):
        decoded = decode_cloudflare_email(encoded)
        if decoded and EMAIL_PATTERN.match(decoded):
            emails.add(decoded)

    # Find mailto links
    mailto_pattern = re.compile(r'mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})', re.IGNORECASE)
    emails.update(mailto_pattern.findall(html_content))

    # Filter false positives
    filtered = set()
    for email in emails:
        email_lower = email.lower()
        if not any(skip in email_lower for skip in ['example.com', 'domain.com', 'yoursite.com', '.png', '.jpg', '.gif', '.css', '.js']):
            filtered.add(email)

    return list(filtered)


def looks_like_address(text):
    """Check if text looks like a mailing address."""
    if not text or len(text) < 10:
        return False
    text_upper = text.upper()
    has_zip = bool(ZIP_PATTERN.search(text))
    has_state = any(f' {state} ' in f' {text_upper} ' or text_upper.endswith(f' {state}') for state in US_STATES)
    has_street = bool(STREET_PATTERN.search(text))
    return sum([has_zip, has_state, has_street]) >= 2


def extract_text_from_html(html_snippet):
    """Remove HTML tags and clean up text."""
    text = re.sub(r'<[^>]+>', ' ', html_snippet)
    text = ' '.join(text.split())
    return text


def extract_footer_content(html_content):
    """Extract content from footer sections."""
    footer_content = []

    # Match <footer> tags
    footer_tag_pattern = re.compile(r'<footer[^>]*>(.*?)</footer>', re.IGNORECASE | re.DOTALL)
    footer_content.extend(footer_tag_pattern.findall(html_content))

    # Match elements with footer-related class or id
    footer_class_pattern = re.compile(
        r'<(?:div|section|nav)[^>]*(?:class|id)=["\'][^"\']*footer[^"\']*["\'][^>]*>(.*?)</(?:div|section|nav)>',
        re.IGNORECASE | re.DOTALL
    )
    footer_content.extend(footer_class_pattern.findall(html_content))

    return footer_content


def extract_location_context(html_content):
    """Extract text surrounding 'located' or 'location' keywords."""
    location_texts = []

    # Remove HTML tags but preserve structure for context extraction
    text_content = extract_text_from_html(html_content)

    # Find sentences/phrases containing location keywords
    location_pattern = re.compile(
        r'[^.]*\b(?:located|location|headquarters|headquartered|office)\b[^.]*\.?',
        re.IGNORECASE
    )

    matches = location_pattern.findall(text_content)
    for match in matches:
        cleaned = match.strip()
        if len(cleaned) > 20 and len(cleaned) < 300:
            location_texts.append(cleaned)

    return location_texts


def extract_addresses(html_content):
    """Extract mailing addresses from page content."""
    addresses = set()
    if not html_content:
        return list(addresses)

    # Simple regex for address-like patterns
    # Look for patterns with street numbers followed by text and ZIP codes
    address_pattern = re.compile(
        r'\d+\s+[A-Za-z0-9\s,\.]+(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln|way|court|ct|place|pl|suite|ste|floor|fl|building|bldg)[A-Za-z0-9\s,\.#-]*\d{5}(?:-\d{4})?',
        re.IGNORECASE
    )

    found = address_pattern.findall(html_content)
    for addr in found:
        cleaned = ' '.join(addr.split())
        if len(cleaned) > 15 and len(cleaned) < 200:
            addresses.add(cleaned)

    # Also look for <address> tags content
    address_tag_pattern = re.compile(r'<address[^>]*>(.*?)</address>', re.IGNORECASE | re.DOTALL)
    for match in address_tag_pattern.findall(html_content):
        text = extract_text_from_html(match)
        if looks_like_address(text) and len(text) < 200:
            addresses.add(text)

    # Search footer sections for addresses
    footer_sections = extract_footer_content(html_content)
    for footer_html in footer_sections:
        footer_text = extract_text_from_html(footer_html)
        # Check if footer text looks like an address
        if looks_like_address(footer_text):
            # Try to extract just the address portion
            found_in_footer = address_pattern.findall(footer_html)
            for addr in found_in_footer:
                cleaned = ' '.join(addr.split())
                if len(cleaned) > 15 and len(cleaned) < 200:
                    addresses.add(cleaned)
        # Also check for address tags within footer
        for match in address_tag_pattern.findall(footer_html):
            text = extract_text_from_html(match)
            if looks_like_address(text) and len(text) < 200:
                addresses.add(text)

    # Search near "located" or "location" keywords
    location_contexts = extract_location_context(html_content)
    for context in location_contexts:
        if looks_like_address(context):
            # Try to extract the address portion from the context
            context_addresses = address_pattern.findall(context)
            for addr in context_addresses:
                cleaned = ' '.join(addr.split())
                if len(cleaned) > 15 and len(cleaned) < 200:
                    addresses.add(cleaned)
            # If no pattern match but looks like address, add the whole context
            if not context_addresses and len(context) < 150:
                addresses.add(context)

    return list(addresses)[:5]


def get_contact_page_urls(base_url, html_content):
    """Find contact page URLs."""
    urls = set()
    if not html_content:
        return list(urls)

    link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    keywords = ['contact', 'about', 'location', 'locations']

    for href in link_pattern.findall(html_content):
        href_lower = href.lower()
        if any(kw in href_lower for kw in keywords):
            if href.startswith('http'):
                full_url = href
            elif href.startswith('/'):
                full_url = urljoin(base_url, href)
            else:
                full_url = urljoin(base_url, '/' + href)

            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                urls.add(full_url)

    return list(urls)[:2]


def scrape_website(url):
    """Scrape a website for emails and addresses."""
    emails = set()
    addresses = set()

    url = normalize_url(url)
    if not url:
        return [], [], "Invalid URL"

    # Fetch main page
    html = fetch_page(url)
    if not html:
        return [], [], "Failed to fetch"

    emails.update(extract_emails(html))
    addresses.update(extract_addresses(html))

    # Check contact pages
    contact_urls = get_contact_page_urls(url, html)
    for contact_url in contact_urls:
        contact_html = fetch_page(contact_url)
        if contact_html:
            emails.update(extract_emails(contact_html))
            addresses.update(extract_addresses(contact_html))

    return list(emails), list(addresses), "OK"


def process_csv_content(csv_content):
    """Process CSV content and return results."""
    reader = csv.reader(io.StringIO(csv_content))
    rows = list(reader)

    if not rows:
        return None, "Empty CSV file"

    header = rows[0]
    data_rows = rows[1:]

    results = []
    max_emails = 0
    max_addresses = 0

    for row in data_rows:
        if not row:
            results.append({'row': row, 'emails': [], 'addresses': [], 'status': 'Empty row'})
            continue

        website = row[0]
        emails, addresses, status = scrape_website(website)
        results.append({
            'row': row,
            'emails': emails,
            'addresses': addresses,
            'status': status
        })
        max_emails = max(max_emails, len(emails))
        max_addresses = max(max_addresses, len(addresses))

    # Build output CSV
    max_emails = max(max_emails, 1)
    max_addresses = max(max_addresses, 1)

    email_headers = [f'email_{i+1}' for i in range(max_emails)]
    address_headers = [f'address_{i+1}' for i in range(max_addresses)]
    new_header = header + email_headers + address_headers + ['scrape_status']

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(new_header)

    for result in results:
        padded_emails = result['emails'] + [''] * (max_emails - len(result['emails']))
        padded_addresses = result['addresses'] + [''] * (max_addresses - len(result['addresses']))
        new_row = result['row'] + padded_emails + padded_addresses + [result['status']]
        writer.writerow(new_row)

    return output.getvalue(), None


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        try:
            data = json.loads(body)
            csv_content = data.get('csv', '')

            if not csv_content:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'No CSV content provided'}).encode())
                return

            result_csv, error = process_csv_content(csv_content)

            if error:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': error}).encode())
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'csv': result_csv}).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
