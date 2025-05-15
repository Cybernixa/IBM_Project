# --- Imports ---
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import dns.resolver
import dns.reversename # Added for reverse DNS
import whois
import requests
from bs4 import BeautifulSoup
# Import sublist3r might still be needed if you conditionally use it,
# but we will disable its execution by default.
try:
    import sublist3r
    SUBLIST3R_AVAILABLE = True
except ImportError:
    SUBLIST3R_AVAILABLE = False
# Import for SMTP
import smtplib
import socket # For detailed socket errors and timeouts

from urllib.parse import urlparse
import re
import logging
import json # Added for crt.sh parsing
from concurrent.futures import ThreadPoolExecutor, as_completed # For parallel checks (like RBL)

# --- Basic Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# List of common DNS Blacklists (this is just a small sample)
# Maintaining a good list is crucial for a real tool.
DNSBL_LIST = [
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "zen.spamhaus.org", # Covers SBL, XBL, PBL
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    # Add many more...
]

# --- Helper Functions (validate_url, add_scheme_if_missing, get_metadata - Keep as before) ---
# ... (Include validate_url, add_scheme_if_missing, get_metadata functions from previous version) ...
def validate_url(url):
    """Validate the URL format (allows domain only or with http/https)."""
    regex = re.compile(
        r'^(?:http[s]?://)?'  # Optional http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S*)?$', re.IGNORECASE) # optional path (allow empty path)
    domain_only_regex = re.compile(
        r'^([A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}$', re.IGNORECASE
    )
    return re.match(regex, url) is not None or re.match(domain_only_regex, url) is not None

def add_scheme_if_missing(url):
    """Adds https:// if URL scheme is missing."""
    if not re.match(r'^(?:http)s?://', url, re.IGNORECASE):
        logging.info(f"Scheme missing, adding https:// to {url}")
        return 'https://' + url
    return url

def get_metadata(url):
    """Extract metadata from the given URL."""
    metadata = {
        'title': 'N/A',
        'description': 'N/A',
        'headers': {},
        'status_code': 'N/A',
        'server': 'N/A',
        'technologies': []
    }
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=20, allow_redirects=True, verify=True)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        metadata['title'] = soup.title.string.strip() if soup.title and soup.title.string else 'No title found'
        description_tag = soup.find('meta', attrs={'name': re.compile(r'^description$', re.I)})
        if description_tag and description_tag.get('content'):
            metadata['description'] = description_tag['content'].strip()
        else:
            metadata['description'] = 'No description found'

        metadata['headers'] = dict(response.headers)
        metadata['status_code'] = response.status_code
        metadata['server'] = response.headers.get('Server', 'Not specified')

        # Basic Tech Detection
        text_lower = response.text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        powered_by = headers_lower.get('x-powered-by', '')
        server_header = headers_lower.get('server', '')

        tech = set() # Use a set to avoid duplicates initially
        if 'wp-content' in text_lower or 'wp-includes' in text_lower: tech.add('WordPress')
        if 'jquery' in text_lower: tech.add('jQuery')
        if 'bootstrap' in text_lower: tech.add('Bootstrap')
        if 'react' in text_lower: tech.add('React')
        if 'php' in powered_by: tech.add('PHP')
        if 'asp.net' in powered_by: tech.add('ASP.NET')
        if 'express' in powered_by: tech.add('ExpressJS (Node.js)')
        if 'cloudflare' in server_header: tech.add('Cloudflare')
        if 'nginx' in server_header: tech.add('Nginx')
        if 'apache' in server_header: tech.add('Apache')
        if 'iis' in server_header: tech.add('Microsoft IIS')

        metadata['technologies'] = sorted(list(tech))
        if not metadata['technologies']:
            metadata['technologies'].append('None detected (basic check)')

        return metadata

    except requests.exceptions.Timeout:
        logging.warning(f"Metadata extraction failed for {url}: Request timed out")
        return {'error': f'Metadata extraction failed: Request timed out'}
    except requests.exceptions.SSLError as e:
        logging.warning(f"Metadata extraction failed for {url}: SSL Error - {e}")
        return {'error': f'Metadata extraction failed: SSL Error - {str(e)}'}
    except requests.exceptions.RequestException as e:
        logging.warning(f"Metadata extraction failed for {url}: {type(e).__name__} - {e}")
        return {'error': f'Metadata extraction failed: {type(e).__name__} - {str(e)}'}
    except Exception as e:
        logging.error(f"Unexpected error in get_metadata for {url}: {e}", exc_info=True)
        return {'error': f'Metadata extraction failed: An unexpected error occurred ({type(e).__name__})'}


# --- DNS & WHOIS Functions (Modified DNS, Keep WHOIS) ---
def get_dns_records(domain):
    """Get DNS records including PTR for IPs found."""
    records = {'PTR': {}} # Add PTR section, storing IP -> Hostname
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    ips_found = {'A': [], 'AAAA': []} # Store IPs to perform PTR lookups later

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1', '8.8.8.8', '1.0.0.1', '8.8.4.4']
    resolver.timeout = 7
    resolver.lifetime = 7
    logging.info(f"Configured DNS resolver with nameservers: {resolver.nameservers} and timeout: {resolver.timeout}s")

    # --- Standard DNS Lookups ---
    for record_type in record_types:
        try:
            logging.info(f"Querying DNS {record_type} for {domain}")
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False) # Don't raise for NoAnswer
            if answers.rrset is None: # Check if rrset is None for NoAnswer
                 logging.info(f"No DNS {record_type} record found for {domain}")
                 records[record_type] = ['No record found']
                 continue

            result_list = sorted([str(rdata) for rdata in answers])
            records[record_type] = result_list
            logging.info(f"DNS {record_type} query successful for {domain}")

            # Store IPs for PTR lookup
            if record_type == 'A':
                ips_found['A'].extend(result_list)
            elif record_type == 'AAAA':
                ips_found['AAAA'].extend(result_list)

        except dns.resolver.NXDOMAIN:
             logging.warning(f"DNS query failed for {domain}: NXDOMAIN")
             return {'error': f'Domain does not exist (NXDOMAIN)'}
        except dns.resolver.Timeout:
            logging.warning(f"DNS query TIMED OUT (>{resolver.timeout}s) for {domain} [{record_type}]")
            records[record_type] = [f'Query timed out (>{resolver.timeout}s)']
        except dns.exception.DNSException as e:
            logging.warning(f"DNS query error for {domain} [{record_type}]: {type(e).__name__} - {e}")
            records[record_type] = [f'Error querying {record_type}: {type(e).__name__}']
        except Exception as e:
            logging.error(f"Unexpected DNS error for {domain} [{record_type}]: {e}", exc_info=True)
            records[record_type] = [f'Unexpected error querying {record_type}']

    # --- Reverse DNS (PTR) Lookups ---
    all_ips = ips_found['A'] + ips_found['AAAA']
    if all_ips:
        logging.info(f"Performing Reverse DNS (PTR) lookups for IPs: {all_ips}")
        for ip in all_ips:
            try:
                addr = dns.reversename.from_address(ip)
                ptr_answers = resolver.resolve(addr, "PTR", raise_on_no_answer=False)
                if ptr_answers.rrset is None:
                     records['PTR'][ip] = 'No PTR record found'
                else:
                     records['PTR'][ip] = sorted([str(rdata) for rdata in ptr_answers])[0] # Usually one PTR
            except dns.resolver.NXDOMAIN:
                 records['PTR'][ip] = 'No PTR record found (NXDOMAIN)'
            except dns.resolver.Timeout:
                 logging.warning(f"PTR query TIMED OUT for IP {ip}")
                 records['PTR'][ip] = f'PTR Query timed out (>{resolver.timeout}s)'
            except dns.exception.DNSException as e:
                 logging.warning(f"PTR query error for IP {ip}: {type(e).__name__}")
                 records['PTR'][ip] = f'PTR Query Error ({type(e).__name__})'
            except Exception as e:
                 logging.error(f"Unexpected PTR error for IP {ip}: {e}", exc_info=True)
                 records['PTR'][ip] = 'Unexpected PTR Error'
        logging.info(f"Completed PTR lookups.")
    else:
         records['PTR'] = {'info': 'No A/AAAA records found to perform reverse lookup.'}


    # Final check on overall results
    has_meaningful_data = any(
         k != 'PTR' and rec_list != ['No record found'] and not rec_list[0].startswith('Error') and not rec_list[0].startswith('Query timed out')
         for k, rec_list in records.items() if k != 'PTR' # Exclude PTR from this check
    )
    if not has_meaningful_data and 'error' not in records:
        all_failed_or_timeout = all(
            (rec_list[0].startswith('Query timed out') or rec_list[0].startswith('Error querying') or rec_list == ['No record found'])
            for k, rec_list in records.items() if k != 'PTR' and rec_list
        )
        if all_failed_or_timeout:
             all_timed_out = all(rec_list[0].startswith('Query timed out') for k, rec_list in records.items() if k != 'PTR' and rec_list and rec_list != ['No record found'])
             if all_timed_out:
                  return {'error': f'All DNS queries timed out (>{resolver.timeout}s). Network issue or target nameservers unreachable.'}
             else:
                  return {'warning': 'Most DNS queries failed or timed out using public resolvers.'}
        else:
            return {'warning': 'Could not resolve any standard DNS records.'}

    # --- Parse specific TXT records (SPF/DMARC/DKIM - Basic) ---
    if 'TXT' in records and isinstance(records['TXT'], list):
        records['SPF'] = [r for r in records['TXT'] if r.lower().startswith('"v=spf1')]
        records['DMARC'] = [r for r in records['TXT'] if r.lower().startswith('"v=dmarc1')]
        # DKIM requires knowing selectors, typically _domainkey subdomain. Can't easily check all possible ones.
        # Add a note that DKIM needs specific selectors.
        records['DKIM_Note'] = "DKIM records usually exist at selector._domainkey subdomain (e.g., google._domainkey.domain.com) and require separate lookups."
        if not records['SPF']: records['SPF'] = ["No SPF record found"]
        if not records['DMARC']: records['DMARC'] = ["No DMARC record found"]

    return records

# ... (Include get_whois_info function from previous version) ...
def get_whois_info(domain):
    """Get WHOIS information for the domain."""
    try:
        logging.info(f"Performing WHOIS lookup on: {domain}")
        w = whois.whois(domain)

        if not w or not w.domain_name:
             if hasattr(w, 'text') and w.text:
                 text_lower = w.text.lower()
                 if "no match" in text_lower or "not found" in text_lower or "no entries found" in text_lower:
                      logging.warning(f"WHOIS lookup for '{domain}' resulted in no match.")
                      return {'error': f'WHOIS lookup failed: No match found for domain "{domain}"'}
             logging.warning(f"WHOIS lookup for '{domain}' returned empty or minimal data.")
             return {'error': f'WHOIS lookup failed: No substantial information returned for "{domain}". It might be newly registered, expired, or have privacy enabled.'}

        def format_date(date_val):
            if not date_val: return 'Not specified'
            date_to_convert = date_val[0] if isinstance(date_val, list) else date_val
            try: return date_to_convert.isoformat()
            except AttributeError: return str(date_to_convert)

        def clean_data(data):
            if isinstance(data, list): return sorted(list(set(filter(None, map(str, data)))))
            elif data: return [str(data)]
            return []

        return {
            'domain_name': clean_data(w.domain_name),
            'registrar': w.registrar or 'Not specified',
            'creation_date': format_date(w.creation_date),
            'expiration_date': format_date(w.expiration_date),
            'last_updated': format_date(w.updated_date),
            'name_servers': clean_data(w.name_servers),
            'status': clean_data(w.status),
            'emails': clean_data(w.emails),
            'dnssec': w.dnssec or 'Not specified',
            'owner': clean_data(w.name), 'org': clean_data(w.org),
            'address': clean_data(w.address), 'city': clean_data(w.city),
            'state': clean_data(w.state), 'zipcode': clean_data(w.zipcode),
            'country': clean_data(w.country),
        }
    except whois.exceptions.UnknownTld:
         logging.warning(f"WHOIS lookup failed for {domain}: Unknown TLD")
         return {'error': f'WHOIS lookup failed: Unknown TLD for domain "{domain}"'}
    except whois.exceptions.WhoisCommandFailed as e:
         logging.error(f"WHOIS command failed for {domain}: {e}", exc_info=True)
         return {'error': f'WHOIS lookup failed: Server communication problem or command issue.'}
    except whois.exceptions.WhoisPrivateRegistry as e:
        logging.warning(f"WHOIS lookup for {domain} indicates a private registry.")
        return {'warning': f'WHOIS information may be limited: Registry for this TLD is private.'}
    except Exception as e:
        logging.error(f"Unexpected error in get_whois_info for {domain}: {e}", exc_info=True)
        return {'error': f'WHOIS lookup failed: An unexpected error occurred ({type(e).__name__})'}

# --- Subdomain Functions (Keep crt.sh only) ---
# ... (Include query_crtsh and get_subdomains functions from previous version, ensuring get_subdomains only calls query_crtsh) ...
def query_crtsh(domain):
    """Queries crt.sh for subdomains based on Certificate Transparency logs."""
    subdomains = set()
    url = f"https://crt.sh/?q={domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; InfoGatherPro/1.0)'}

    logging.info(f"Querying crt.sh for {domain}")
    try:
        response = requests.get(url, headers=headers, timeout=25)
        response.raise_for_status()

        if not response.text:
            logging.warning(f"crt.sh returned empty response for {domain}")
            return set()

        try:
            data = response.json()
            if not isinstance(data, list):
                 logging.error(f"crt.sh returned unexpected JSON structure (not a list) for {domain}")
                 return {'error': 'crt.sh returned invalid data structure.'}
        except json.JSONDecodeError:
             logging.error(f"crt.sh returned non-JSON response for {domain}: {response.text[:100]}...")
             return {'error': 'crt.sh returned invalid data (non-JSON).'}

        for entry in data:
            potential_names = []
            if 'common_name' in entry: potential_names.append(entry['common_name'])
            if 'name_value' in entry: potential_names.extend(entry['name_value'].split('\n'))

            for name in potential_names:
                name = name.lower().strip()
                if name.endswith(f".{domain}") and name != domain and not name.startswith('*.'):
                    if re.match(r'^[a-z0-9.-]+$', name): subdomains.add(name)

        logging.info(f"Found {len(subdomains)} unique subdomains via crt.sh for {domain}")
        return subdomains

    except requests.exceptions.Timeout:
         logging.warning(f"crt.sh query timed out for {domain}")
         return {'error': 'crt.sh query timed out.'}
    except requests.exceptions.RequestException as e:
        logging.error(f"crt.sh query failed for {domain}: {e}")
        return {'error': f'crt.sh query failed ({type(e).__name__}).'}
    except Exception as e:
        logging.error(f"Unexpected error querying crt.sh for {domain}: {e}", exc_info=True)
        return {'error': f'Unexpected error during crt.sh query ({type(e).__name__}).'}

def get_subdomains(domain):
    """
    Enumerate subdomains using crt.sh ONLY. Sublist3r is disabled.
    Returns a dictionary containing results, status, and any errors.
    """
    all_subdomains = set()
    results_log = {'crtsh': 'Not Run', 'sublist3r': 'Disabled'}
    errors = []

    # --- Method 1: crt.sh ---
    crtsh_result = query_crtsh(domain)
    if isinstance(crtsh_result, set):
        count = len(crtsh_result)
        all_subdomains.update(crtsh_result)
        results_log['crtsh'] = f"Success ({count} found)"
    elif isinstance(crtsh_result, dict) and 'error' in crtsh_result:
        error_msg = f"crt.sh Error: {crtsh_result['error']}"
        errors.append(error_msg)
        results_log['crtsh'] = f"Failed ({crtsh_result['error']})"
        logging.warning(error_msg)
    else:
        error_msg = "crt.sh Error: Unknown return type."
        errors.append(error_msg)
        results_log['crtsh'] = "Failed (Unknown)"
        logging.error(error_msg)

    # --- Consolidate Results ---
    final_list = sorted(list(all_subdomains))
    summary_msg = f"Found {len(final_list)} total unique subdomains (using crt.sh)."
    if errors: summary_msg += f" Encountered {len(errors)} error(s) during enumeration."

    output = {
        'summary': summary_msg, 'sources_status': results_log,
        'subdomains': final_list if final_list else ["No subdomains found by crt.sh."],
        'errors': errors if errors else ["No critical errors encountered during subdomain enumeration."]
    }
    if not final_list and errors:
         output['subdomains'] = ["No subdomains discovered via crt.sh. Errors occurred during enumeration (see errors list)."]

    return output

# --- NEW: SMTP Check Function (Basic Structure) ---
def check_smtp_server(server_ip, server_hostname, domain):
    """Performs basic SMTP connection tests on a given mail server."""
    result = {'status': 'Not Run', 'banner': None, 'connect_time_ms': None, 'errors': []}
    smtp_port = 25 # Standard SMTP port
    start_time = time.time()

    try:
        logging.info(f"Attempting SMTP connection to {server_hostname} ({server_ip}) on port {smtp_port}")
        # Use socket timeout for the connection itself
        # smtplib timeout applies to commands after connection
        with smtplib.SMTP(server_ip, smtp_port, timeout=10) as server:
            result['connect_time_ms'] = round((time.time() - start_time) * 1000)
            result['banner'] = server.getwelcome().strip()
            logging.info(f"SMTP connected to {server_hostname}, banner: {result['banner']}")

            # Optional: Add more checks here (HELO, STARTTLS check, etc.)
            # Example: HELO command
            try:
                 helo_resp_code, helo_resp_msg = server.helo(f"check.{domain}") # Use a generic HELO name
                 if helo_resp_code != 250:
                      result['errors'].append(f"HELO command failed: {helo_resp_code} {helo_resp_msg.decode(errors='ignore')}")
                 else:
                      logging.info(f"HELO command successful on {server_hostname}")
            except Exception as helo_e:
                 result['errors'].append(f"Error during HELO: {type(helo_e).__name__}")
                 logging.warning(f"HELO command error on {server_hostname}: {helo_e}")

            # NOTE: Checking for open relay is complex and potentially dangerous. Omitted here.

            result['status'] = 'Success'

    except smtplib.SMTPConnectError as e:
        result['status'] = 'Failed (Connection Error)'
        result['errors'].append(f"Connection Error: {e}")
        logging.warning(f"SMTP connection error to {server_hostname}: {e}")
    except smtplib.SMTPHeloError as e:
        result['status'] = 'Failed (HELO Error)'
        result['errors'].append(f"HELO Error: {e}")
        logging.warning(f"SMTP HELO error on {server_hostname}: {e}")
    except smtplib.SMTPServerDisconnected as e:
        result['status'] = 'Failed (Disconnected)'
        result['errors'].append(f"Server disconnected unexpectedly: {e}")
        logging.warning(f"SMTP server disconnected {server_hostname}: {e}")
    except socket.timeout:
        result['status'] = 'Failed (Timeout)'
        result['errors'].append("Connection or command timed out (>10s)")
        logging.warning(f"SMTP timeout connecting/communicating with {server_hostname}")
    except socket.error as e: # Catch specific socket errors like refused connection
        result['status'] = 'Failed (Socket Error)'
        result['errors'].append(f"Socket Error: {e}")
        logging.warning(f"SMTP socket error for {server_hostname}: {e}")
    except Exception as e:
        result['status'] = 'Failed (Unexpected Error)'
        result['errors'].append(f"Unexpected Error: {type(e).__name__} - {e}")
        logging.error(f"Unexpected SMTP error for {server_hostname}: {e}", exc_info=True)

    if not result['errors']:
        result['errors'] = ["No errors encountered."] # Placeholder if successful

    return result

def get_smtp_diagnostics(domain, dns_results):
    """Orchestrates SMTP checks for servers found in MX records."""
    smtp_results = {}
    mx_records = dns_results.get('MX', [])
    resolver = dns.resolver.Resolver() # Use default resolver for MX IP lookups for simplicity here
    resolver.timeout = 5
    resolver.lifetime = 5

    if not mx_records or mx_records == ['No record found']:
        return {'info': 'No MX records found to perform SMTP checks.'}

    # Process MX records (format: "preference hostname")
    mail_servers = []
    for record in mx_records:
        parts = record.split()
        if len(parts) == 2:
            try:
                preference = int(parts[0])
                hostname = parts[1].rstrip('.') # Remove trailing dot if present
                mail_servers.append({'preference': preference, 'hostname': hostname})
            except ValueError:
                logging.warning(f"Could not parse MX record: {record}")
        else:
             logging.warning(f"Could not parse MX record: {record}")

    if not mail_servers:
         return {'error': 'Could not parse any valid MX hostnames.'}

    # Sort by preference (lower is better)
    mail_servers.sort(key=lambda x: x['preference'])

    logging.info(f"Found MX servers to check: {mail_servers}")

    # Check each server
    for server in mail_servers:
        hostname = server['hostname']
        server_ips = []
        errors = []

        # Resolve hostname to IP(s)
        try:
            a_answers = resolver.resolve(hostname, 'A', raise_on_no_answer=False)
            if a_answers.rrset: server_ips.extend([str(rdata) for rdata in a_answers])
        except Exception as e: errors.append(f"A record lookup failed: {type(e).__name__}")
        try:
             aaaa_answers = resolver.resolve(hostname, 'AAAA', raise_on_no_answer=False)
             if aaaa_answers.rrset: server_ips.extend([str(rdata) for rdata in aaaa_answers])
        except Exception as e: errors.append(f"AAAA record lookup failed: {type(e).__name__}")


        if not server_ips:
            smtp_results[f"{hostname} (Pref {server['preference']})"] = {'status': 'Failed (Resolution)', 'errors': errors or ["Could not resolve hostname to IP address."]}
            continue

        # Check first resolved IP for simplicity (MXToolbox might check more)
        first_ip = server_ips[0]
        logging.info(f"Checking SMTP for {hostname} at IP {first_ip}")
        smtp_check_result = check_smtp_server(first_ip, hostname, domain)
        smtp_results[f"{hostname} (Pref {server['preference']})"] = smtp_check_result

    return smtp_results


# --- NEW: Blacklist Check Functions (Basic Structure) ---
def check_ip_dnsbl(ip, dnsbl_server, resolver):
    """Checks a single IP against a single DNSBL server."""
    try:
        # Format IP for DNSBL query (reverse octets/parts + dnsbl server)
        if ':' in ip: # IPv6 - very basic reversal, needs improvement for full spec
            # Simplified: reverse hex groups, join with dots, append server
            # Proper IPv6 reversal is more complex. This is illustrative only.
             parts = ip.split(':')
             # Very basic - might not work for all IPv6 formats
             rev_ip = ".".join(reversed("".join(parts))) + "." + dnsbl_server
        else: # IPv4
            rev_ip = ".".join(reversed(ip.split('.'))) + "." + dnsbl_server

        logging.info(f"Checking DNSBL {dnsbl_server} for {ip} via {rev_ip}")
        resolver.resolve(rev_ip, 'A') # Check if A record exists
        logging.warning(f"IP {ip} IS LISTED on {dnsbl_server}")
        return dnsbl_server, True # Found A record -> Listed
    except dns.resolver.NXDOMAIN:
        logging.info(f"IP {ip} not listed on {dnsbl_server}")
        return dnsbl_server, False # NXDOMAIN -> Not listed
    except dns.resolver.Timeout:
        logging.warning(f"DNSBL check timed out for {ip} on {dnsbl_server}")
        return dnsbl_server, "Timeout"
    except Exception as e:
        logging.error(f"Error checking DNSBL {dnsbl_server} for {ip}: {e}")
        return dnsbl_server, f"Error ({type(e).__name__})"

def get_blacklist_checks(domain, dns_results):
    """Orchestrates DNSBL checks for IPs found in A/AAAA/MX records."""
    blacklist_results = {'summary': {}, 'details': {}}
    ips_to_check = set()

    # Get primary A/AAAA records
    if isinstance(dns_results.get('A'), list): ips_to_check.update(ip for ip in dns_results['A'] if '.' in ip) # Basic validation
    if isinstance(dns_results.get('AAAA'), list): ips_to_check.update(ip for ip in dns_results['AAAA'] if ':' in ip) # Basic validation

    # Get IPs of MX servers
    mx_records = dns_results.get('MX', [])
    resolver = dns.resolver.Resolver() # Use default for simplicity again
    resolver.timeout = 5
    resolver.lifetime = 5
    if isinstance(mx_records, list) and mx_records != ['No record found']:
         for record in mx_records:
             parts = record.split()
             if len(parts) == 2:
                 hostname = parts[1].rstrip('.')
                 try:
                     a_answers = resolver.resolve(hostname, 'A', raise_on_no_answer=False)
                     if a_answers.rrset: ips_to_check.update(str(rdata) for rdata in a_answers)
                 except Exception: pass # Ignore resolution errors here
                 try:
                      aaaa_answers = resolver.resolve(hostname, 'AAAA', raise_on_no_answer=False)
                      if aaaa_answers.rrset: ips_to_check.update(str(rdata) for rdata in aaaa_answers)
                 except Exception: pass # Ignore resolution errors here

    if not ips_to_check:
        return {'info': 'No IPs found (A/AAAA/MX) to check against blacklists.'}

    logging.info(f"Checking IPs against DNSBLs: {list(ips_to_check)}")

    # Configure resolver for DNSBL checks
    dnsbl_resolver = dns.resolver.Resolver()
    dnsbl_resolver.nameservers = ['1.1.1.1', '8.8.8.8'] # Use reliable public ones
    dnsbl_resolver.timeout = 5
    dnsbl_resolver.lifetime = 5

    listed_count = 0
    error_count = 0
    timeout_count = 0

    # Use ThreadPoolExecutor for parallel DNSBL checks
    # Be mindful of potential rate limits from DNS servers or DNSBLs themselves
    max_workers = 10 # Adjust as needed
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for ip in ips_to_check:
            blacklist_results['details'][ip] = {}
            for dnsbl in DNSBL_LIST:
                 # Submit task: check_ip_dnsbl(ip, dnsbl, dnsbl_resolver)
                 future = executor.submit(check_ip_dnsbl, ip, dnsbl, dnsbl_resolver)
                 futures[future] = (ip, dnsbl) # Store context

        for future in as_completed(futures):
            ip, dnsbl = futures[future]
            try:
                dnsbl_server_returned, result = future.result()
                blacklist_results['details'][ip][dnsbl_server_returned] = result
                if result is True:
                    listed_count += 1
                elif result == "Timeout":
                    timeout_count += 1
                elif isinstance(result, str) and "Error" in result:
                     error_count += 1
            except Exception as exc:
                logging.error(f"Exception getting result for DNSBL check ({ip} on {dnsbl}): {exc}")
                blacklist_results['details'][ip][dnsbl] = f"Execution Error ({type(exc).__name__})"
                error_count += 1

    blacklist_results['summary'] = {
        'ips_checked': len(ips_to_check),
        'blacklists_queried': len(DNSBL_LIST),
        'listings_found': listed_count,
        'timeouts': timeout_count,
        'errors': error_count
    }
    logging.info(f"Blacklist check summary: {blacklist_results['summary']}")

    return blacklist_results


# --- Flask Routes ---
@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Main endpoint for scanning a URL, performing multiple checks."""
    if not request.is_json:
        logging.warning("Received non-JSON request to /scan")
        return jsonify({'error': 'Request must be JSON'}), 415

    data = request.get_json()
    url_input = data.get('url')

    if not url_input:
        logging.warning("Received scan request with no URL")
        return jsonify({'error': 'No URL provided'}), 400

    url_input = url_input.strip()
    if not validate_url(url_input):
        logging.warning(f"Received scan request with invalid URL format: {url_input}")
        return jsonify({'error': 'Invalid URL format provided. Use domain.com or http(s)://domain.com'}), 400

    full_url = add_scheme_if_missing(url_input)

    try:
        parsed_url = urlparse(full_url)
        domain = parsed_url.netloc
        if ':' in domain: domain = domain.split(':')[0] # Remove port

        if not domain:
             logging.error(f"Could not extract domain from validated URL: {full_url}")
             return jsonify({'error': 'Could not extract domain from URL'}), 400

        logging.info(f"--- Starting Comprehensive Scan for Domain: {domain} ---")

        # --- Perform checks sequentially, passing results as needed ---
        scan_results = {
            'target_url': full_url, 'target_domain': domain,
            'metadata': None, 'dns_records': None, 'whois': None,
            'smtp_diagnostics': None, 'blacklist_checks': None,
            'subdomains': None,
        }

        # 1. DNS Records (includes PTR and basic SPF/DMARC parsing)
        logging.info(f"Step 1: Performing DNS lookups for {domain}")
        dns_results = get_dns_records(domain)
        scan_results['dns_records'] = dns_results

        # Only proceed if DNS lookups didn't completely fail (e.g., NXDOMAIN)
        if isinstance(dns_results, dict) and 'error' in dns_results and dns_results['error'].endswith('(NXDOMAIN)'):
             logging.error(f"Scan aborted for {domain}: Domain does not exist (NXDOMAIN).")
             # Return partial results maybe? Or just the error.
             return jsonify(scan_results) # Return what we have (mostly error)
        # Optional: Check for complete timeout scenario as well
        if isinstance(dns_results, dict) and 'error' in dns_results and 'All DNS queries timed out' in dns_results['error']:
             logging.error(f"Scan potentially incomplete for {domain}: All DNS queries timed out.")
             # Continue with other checks that don't rely on DNS, but mark DNS as failed.

        # 2. WHOIS
        logging.info(f"Step 2: Performing WHOIS lookup for {domain}")
        scan_results['whois'] = get_whois_info(domain)

        # 3. Subdomains (crt.sh)
        logging.info(f"Step 3: Performing Subdomain lookup for {domain}")
        scan_results['subdomains'] = get_subdomains(domain)

        # 4. Metadata (Web Server Check) - Needs full URL
        logging.info(f"Step 4: Performing Metadata check for {full_url}")
        scan_results['metadata'] = get_metadata(full_url)

        # 5. SMTP Diagnostics (Needs DNS results for MX)
        logging.info(f"Step 5: Performing SMTP diagnostics for {domain}")
        if isinstance(dns_results, dict) and 'error' not in dns_results: # Check DNS didn't error out
             scan_results['smtp_diagnostics'] = get_smtp_diagnostics(domain, dns_results)
        else:
             scan_results['smtp_diagnostics'] = {'info': 'Skipped due to DNS errors.'}

        # 6. Blacklist Checks (Needs DNS results for IPs)
        logging.info(f"Step 6: Performing Blacklist checks for {domain}")
        if isinstance(dns_results, dict) and 'error' not in dns_results:
             scan_results['blacklist_checks'] = get_blacklist_checks(domain, dns_results)
        else:
             scan_results['blacklist_checks'] = {'info': 'Skipped due to DNS errors.'}


        logging.info(f"--- Comprehensive Scan Completed for Domain: {domain} ---")
        return jsonify(scan_results)

    except Exception as e:
        # Catch-all for unexpected errors in the main scan logic
        logging.error(f"Critical error during scan orchestration for {url_input}: {e}", exc_info=True)
        return jsonify({'error': f'An unexpected server error occurred during the scan orchestration: {type(e).__name__}'}), 500

# --- Main Execution ---
# Need to import time for SMTP connect timing
import time

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)