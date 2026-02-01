#!/usr/bin/env python3
"""
Website Scraper - Extracts email and mailing addresses from websites listed in a CSV file.
"""

import csv
import re
import sys
import argparse
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup


# Regex pattern for email addresses
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# Cloudflare email protection pattern
CF_EMAIL_PATTERN = re.compile(r'data-cfemail="([a-fA-F0-9]+)"')
CF_EMAIL_HREF_PATTERN = re.compile(r'/cdn-cgi/l/email-protection#([a-fA-F0-9]+)')

# Common patterns that indicate mailing addresses
ADDRESS_KEYWORDS = [
    'address', 'location', 'headquarters', 'office', 'contact',
    'street', 'avenue', 'boulevard', 'road', 'drive', 'lane',
    'suite', 'floor', 'building'
]

# US state abbreviations and names for address detection
US_STATES = {
    'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
    'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
    'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
    'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
    'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY',
    'DC', 'PR'
}

# Regex for US ZIP codes
ZIP_PATTERN = re.compile(r'\b\d{5}(?:-\d{4})?\b')

# Regex for street addresses
STREET_PATTERN = re.compile(
    r'\b\d+\s+[\w\s]+(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln|way|court|ct|place|pl|circle|cir)\b',
    re.IGNORECASE
)


def decode_cloudflare_email(encoded_string):
    """Decode Cloudflare's email protection encoding."""
    try:
        # First two hex chars are the XOR key
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


def fetch_page(url, timeout=10):
    """Fetch a webpage and return its content."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"  Error fetching {url}: {e}")
        return None


def extract_emails(html_content, soup):
    """Extract email addresses from page content."""
    emails = set()

    # Find emails in raw HTML/text
    if html_content:
        found = EMAIL_PATTERN.findall(html_content)
        emails.update(found)

        # Find Cloudflare-protected emails in data-cfemail attributes
        cf_emails = CF_EMAIL_PATTERN.findall(html_content)
        for encoded in cf_emails:
            decoded = decode_cloudflare_email(encoded)
            if decoded and EMAIL_PATTERN.match(decoded):
                emails.add(decoded)

        # Find Cloudflare-protected emails in href links
        cf_hrefs = CF_EMAIL_HREF_PATTERN.findall(html_content)
        for encoded in cf_hrefs:
            decoded = decode_cloudflare_email(encoded)
            if decoded and EMAIL_PATTERN.match(decoded):
                emails.add(decoded)

    # Find emails in mailto links
    if soup:
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('mailto:'):
                email = href[7:].split('?')[0]  # Remove mailto: and any parameters
                if EMAIL_PATTERN.match(email):
                    emails.add(email)

        # Find elements with data-cfemail attribute
        for elem in soup.find_all(attrs={'data-cfemail': True}):
            encoded = elem['data-cfemail']
            decoded = decode_cloudflare_email(encoded)
            if decoded and EMAIL_PATTERN.match(decoded):
                emails.add(decoded)

    # Filter out common false positives
    filtered_emails = set()
    for email in emails:
        email_lower = email.lower()
        # Skip common non-email patterns
        if not any(skip in email_lower for skip in ['example.com', 'domain.com', 'email.com', 'yoursite.com', '.png', '.jpg', '.gif', '.css', '.js']):
            filtered_emails.add(email)

    return list(filtered_emails)


def extract_addresses(soup):
    """Extract mailing addresses from page content."""
    addresses = set()

    if not soup:
        return list(addresses)

    # Get all text content
    text = soup.get_text(separator=' ', strip=True)

    # Look for address elements
    address_elements = soup.find_all('address')
    for elem in address_elements:
        addr_text = elem.get_text(separator=' ', strip=True)
        if addr_text and len(addr_text) > 10:
            addresses.add(clean_address(addr_text))

    # Look for elements with address-related classes or IDs
    for keyword in ['address', 'location', 'contact-info', 'headquarters']:
        elements = soup.find_all(class_=re.compile(keyword, re.IGNORECASE))
        elements += soup.find_all(id=re.compile(keyword, re.IGNORECASE))
        for elem in elements:
            addr_text = elem.get_text(separator=' ', strip=True)
            if looks_like_address(addr_text):
                addresses.add(clean_address(addr_text))

    # Look for structured address data (schema.org)
    for elem in soup.find_all(itemtype=re.compile('PostalAddress', re.IGNORECASE)):
        addr_text = elem.get_text(separator=' ', strip=True)
        if addr_text:
            addresses.add(clean_address(addr_text))

    # Look for address patterns in text blocks
    for elem in soup.find_all(['p', 'div', 'span', 'li']):
        elem_text = elem.get_text(separator=' ', strip=True)
        if looks_like_address(elem_text) and len(elem_text) < 300:
            addresses.add(clean_address(elem_text))

    # Filter and deduplicate
    filtered = []
    for addr in addresses:
        if addr and len(addr) > 15 and len(addr) < 250:
            # Check it's not just a phone number or email
            if not EMAIL_PATTERN.search(addr) or STREET_PATTERN.search(addr):
                filtered.append(addr)

    return filtered[:5]  # Limit to 5 addresses max


def looks_like_address(text):
    """Check if text looks like a mailing address."""
    if not text or len(text) < 10:
        return False

    text_upper = text.upper()

    # Check for ZIP code
    has_zip = bool(ZIP_PATTERN.search(text))

    # Check for state abbreviation
    has_state = any(f' {state} ' in f' {text_upper} ' or text_upper.endswith(f' {state}') for state in US_STATES)

    # Check for street pattern
    has_street = bool(STREET_PATTERN.search(text))

    # Must have at least 2 of: ZIP, state, street pattern
    score = sum([has_zip, has_state, has_street])
    return score >= 2


def clean_address(text):
    """Clean up an address string."""
    # Remove excessive whitespace
    text = ' '.join(text.split())
    # Remove common prefixes
    for prefix in ['Address:', 'Location:', 'Headquarters:', 'Office:']:
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    return text


def get_contact_pages(base_url, soup):
    """Find links to contact/about pages that might have address info."""
    contact_urls = []

    if not soup:
        return contact_urls

    keywords = ['contact', 'about', 'location', 'office', 'headquarters']

    for link in soup.find_all('a', href=True):
        href = link['href'].lower()
        text = link.get_text().lower()

        if any(kw in href or kw in text for kw in keywords):
            full_url = urljoin(base_url, link['href'])
            # Only include URLs from same domain
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                contact_urls.append(full_url)

    return list(set(contact_urls))[:3]  # Limit to 3 additional pages


def scrape_website(url):
    """Scrape a website for emails and addresses."""
    emails = set()
    addresses = set()

    url = normalize_url(url)
    if not url:
        return [], []

    print(f"  Scraping: {url}")

    # Fetch main page
    html = fetch_page(url)
    if not html:
        return [], []

    soup = BeautifulSoup(html, 'html.parser')

    # Extract from main page
    emails.update(extract_emails(html, soup))
    addresses.update(extract_addresses(soup))

    # Find and scrape contact pages
    contact_pages = get_contact_pages(url, soup)
    for contact_url in contact_pages:
        print(f"    Checking: {contact_url}")
        contact_html = fetch_page(contact_url)
        if contact_html:
            contact_soup = BeautifulSoup(contact_html, 'html.parser')
            emails.update(extract_emails(contact_html, contact_soup))
            addresses.update(extract_addresses(contact_soup))

    return list(emails), list(addresses)


def process_csv(input_file, output_file=None):
    """Process a CSV file and add email/address columns."""
    if output_file is None:
        # Create output filename
        if input_file.endswith('.csv'):
            output_file = input_file[:-4] + '_scraped.csv'
        else:
            output_file = input_file + '_scraped.csv'

    # Read input CSV
    with open(input_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        rows = list(reader)

    if not rows:
        print("Error: CSV file is empty")
        return

    header = rows[0]
    data_rows = rows[1:]

    print(f"Processing {len(data_rows)} websites...")

    # Track max number of emails and addresses found
    max_emails = 0
    max_addresses = 0
    results = []

    for i, row in enumerate(data_rows):
        if not row:
            results.append(([], []))
            continue

        website = row[0]
        print(f"\n[{i+1}/{len(data_rows)}] Processing: {website}")

        emails, addresses = scrape_website(website)
        results.append((emails, addresses))

        max_emails = max(max_emails, len(emails))
        max_addresses = max(max_addresses, len(addresses))

        if emails:
            print(f"  Found {len(emails)} email(s): {', '.join(emails[:3])}{'...' if len(emails) > 3 else ''}")
        if addresses:
            print(f"  Found {len(addresses)} address(es)")

    # Ensure at least one column for each
    max_emails = max(max_emails, 1)
    max_addresses = max(max_addresses, 1)

    # Build new header
    email_headers = [f'email_{i+1}' for i in range(max_emails)]
    address_headers = [f'address_{i+1}' for i in range(max_addresses)]
    new_header = header + email_headers + address_headers

    # Build output rows
    output_rows = [new_header]
    for row, (emails, addresses) in zip(data_rows, results):
        # Pad emails and addresses to max length
        padded_emails = emails + [''] * (max_emails - len(emails))
        padded_addresses = addresses + [''] * (max_addresses - len(addresses))
        new_row = row + padded_emails + padded_addresses
        output_rows.append(new_row)

    # Write output CSV
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(output_rows)

    print(f"\n✓ Results saved to: {output_file}")
    print(f"  - Added {max_emails} email column(s)")
    print(f"  - Added {max_addresses} address column(s)")


def main():
    parser = argparse.ArgumentParser(
        description='Scrape websites from CSV for email and mailing addresses'
    )
    parser.add_argument('input_file', help='Input CSV file with websites in first column')
    parser.add_argument('-o', '--output', help='Output CSV file (default: input_scraped.csv)')

    args = parser.parse_args()

    process_csv(args.input_file, args.output)


if __name__ == '__main__':
    main()
