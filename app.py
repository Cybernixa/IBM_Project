# --- app.py ---
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
import time # For SMTP connect timing

# --- Basic Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# List of common DNS Blacklists (this is just a small sample)
DNSBL_LIST = [
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
]

# --- Helper Functions ---
def validate_url(url):
    regex = re.compile(
        r'^(?:http[s]?://)?'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S*)?$', re.IGNORECASE)
    domain_only_regex = re.compile(
        r'^([A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}$', re.IGNORECASE
    )
    return re.match(regex, url) is not None or re.match(domain_only_regex, url) is not None

def add_scheme_if_missing(url):
    if not re.match(r'^(?:http)s?://', url, re.IGNORECASE):
        logging.info(f"Scheme missing, adding https:// to {url}")
        return 'https://' + url
    return url

def get_metadata(url):
    metadata = {
        'title': 'N/A',
        'description': 'N/A',
        'headers': {},
        'status_code': 'N/A',
        'server': 'N/A',
        'technologies': []
    }
    try:
        headers_req = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers_req, timeout=20, allow_redirects=True, verify=True)
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

        text_lower = response.text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        powered_by = headers_lower.get('x-powered-by', '')
        server_header = headers_lower.get('server', '')

        tech = set()
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

# --- NEW: Security Headers Check Function ---
def check_security_headers(headers_dict):
    """Analyzes HTTP headers for common security configurations."""
    findings = {
        'present': [],
        'missing': [],
        'warnings': [],
        'recommendations': [], 
        'info': "Scan initiated." 
    }
    normalized_headers = {k.lower(): v for k, v in headers_dict.items()}

    # Strict-Transport-Security (HSTS)
    if 'strict-transport-security' in normalized_headers:
        findings['present'].append(f"Strict-Transport-Security (HSTS): {normalized_headers['strict-transport-security']}")
    else:
        findings['missing'].append('Strict-Transport-Security (HSTS)')
        findings['recommendations'].append("Implement HSTS to enforce HTTPS, protecting against protocol downgrade attacks and cookie hijacking.")

    # X-Frame-Options
    xfo_header = normalized_headers.get('x-frame-options', '').lower()
    if xfo_header:
        findings['present'].append(f"X-Frame-Options: {normalized_headers['x-frame-options']}")
        if not (xfo_header == 'deny' or xfo_header == 'sameorigin'):
            findings['warnings'].append(f"X-Frame-Options is '{xfo_header}'. Consider 'DENY' or 'SAMEORIGIN' for stronger clickjacking protection.")
    else:
        findings['missing'].append('X-Frame-Options')
        findings['recommendations'].append("Implement X-Frame-Options (e.g., 'DENY' or 'SAMEORIGIN') to protect against clickjacking attacks.")

    # X-Content-Type-Options
    xcto_header = normalized_headers.get('x-content-type-options', '').lower()
    if xcto_header:
        if xcto_header == 'nosniff':
            findings['present'].append('X-Content-Type-Options: nosniff')
        else:
            findings['warnings'].append(f"X-Content-Type-Options is '{xcto_header}'. It should be 'nosniff'.")
            findings['recommendations'].append("Set X-Content-Type-Options to 'nosniff' to prevent MIME-type sniffing attacks.")
    else:
        findings['missing'].append('X-Content-Type-Options')
        findings['recommendations'].append("Implement X-Content-Type-Options: nosniff to prevent browsers from MIME-sniffing a response away from the declared content-type.")

    # Content-Security-Policy (CSP)
    csp_header_key = None
    if 'content-security-policy' in normalized_headers:
        csp_header_key = 'content-security-policy'
    elif 'x-content-security-policy' in normalized_headers: 
        csp_header_key = 'x-content-security-policy'
        findings['warnings'].append("Using deprecated 'X-Content-Security-Policy' header. Use 'Content-Security-Policy'.")

    if csp_header_key:
        csp_value = normalized_headers[csp_header_key]
        findings['present'].append(f"Content-Security-Policy: {csp_value[:100]}{'...' if len(csp_value) > 100 else ''}") 
        if "'unsafe-inline'" in csp_value and "script-src" in csp_value:
            findings['warnings'].append("CSP contains 'unsafe-inline' for script-src, which reduces XSS protection. Consider using nonces or hashes.")
        if "'unsafe-eval'" in csp_value and "script-src" in csp_value:
            findings['warnings'].append("CSP contains 'unsafe-eval' for script-src, which can be risky. Avoid if possible.")
        if not csp_value.strip():
            findings['warnings'].append("Content-Security-Policy header is present but empty.")
    else:
        findings['missing'].append('Content-Security-Policy (CSP)')
        findings['recommendations'].append("Implement Content-Security-Policy (CSP) as a powerful defense against XSS and data injection attacks.")

    # Referrer-Policy
    if 'referrer-policy' in normalized_headers:
        findings['present'].append(f"Referrer-Policy: {normalized_headers['referrer-policy']}")
    else:
        findings['missing'].append('Referrer-Policy')
        findings['recommendations'].append("Consider implementing Referrer-Policy to control how much referrer information is sent with requests.")

    # Permissions-Policy (formerly Feature-Policy)
    pp_header_key = None
    if 'permissions-policy' in normalized_headers:
        pp_header_key = 'permissions-policy'
    elif 'feature-policy' in normalized_headers:
        pp_header_key = 'feature-policy'
        findings['warnings'].append("Using deprecated 'Feature-Policy' header. Use 'Permissions-Policy'.")
    
    if pp_header_key:
        findings['present'].append(f"Permissions-Policy: {normalized_headers[pp_header_key][:100]}{'...' if len(normalized_headers[pp_header_key]) > 100 else ''}")
    else:
        findings['missing'].append('Permissions-Policy')
        findings['recommendations'].append("Consider implementing Permissions-Policy to control which browser features can be used by the page.")

    # Server Header Disclosure
    server_header_val = normalized_headers.get('server', '')
    if server_header_val and server_header_val.lower() != 'not specified' and server_header_val.lower() != 'n/a':
        if re.search(r'[\w.-]+/[\d.]+', server_header_val) or len(server_header_val.split('/')) > 1 :
            findings['warnings'].append(f"Server header may reveal specific software/version: '{server_header_val}'. Consider minimizing this information.")
            findings['recommendations'].append("Obscure or remove detailed version information from the 'Server' header to reduce information leakage.")
        else:
            findings['present'].append(f"Server: {server_header_val} (Version information seems minimal or absent)")

    # X-Powered-By Header Disclosure
    x_powered_by_val = normalized_headers.get('x-powered-by', '')
    if x_powered_by_val:
        findings['warnings'].append(f"X-Powered-By header reveals technology: '{x_powered_by_val}'. This header should ideally be removed.")
        findings['recommendations'].append("Remove the 'X-Powered-By' header to avoid disclosing server-side technology.")

    if not findings['missing'] and not findings['warnings']:
        findings['info'] = "Good! Most common security headers are present and configured reasonably well."
    elif not findings['missing'] and findings['warnings']:
        findings['info'] = "Most common security headers are present, but some have configurations that could be improved."
    elif findings['missing']:
        findings['info'] = "Several important security headers are missing. Review recommendations for improvements."
    else: 
        findings['info'] = "Security header check completed."

    if not findings['present']: findings['present'] = ["None of the commonly checked security headers were found."]
    if not findings['missing']: findings['missing'] = ["No commonly checked security headers appear to be missing (based on those found)."]
    if not findings['warnings']: findings['warnings'] = ["No specific configuration warnings for present headers."]
    if not findings['recommendations']: findings['recommendations'] = ["No immediate recommendations based on missing/misconfigured common headers."]

    return findings


# --- DNS & WHOIS Functions ---
def get_dns_records(domain):
    records = {'PTR': {}}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    ips_found = {'A': [], 'AAAA': []}

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1', '8.8.8.8', '1.0.0.1', '8.8.4.4']
    resolver.timeout = 7
    resolver.lifetime = 7
    logging.info(f"Configured DNS resolver with nameservers: {resolver.nameservers} and timeout: {resolver.timeout}s")

    for record_type in record_types:
        try:
            logging.info(f"Querying DNS {record_type} for {domain}")
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answers.rrset is None:
                 logging.info(f"No DNS {record_type} record found for {domain}")
                 records[record_type] = ['No record found']
                 continue
            result_list = sorted([str(rdata) for rdata in answers])
            records[record_type] = result_list
            logging.info(f"DNS {record_type} query successful for {domain}")
            if record_type == 'A': ips_found['A'].extend(result_list)
            elif record_type == 'AAAA': ips_found['AAAA'].extend(result_list)
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

    all_ips = ips_found['A'] + ips_found['AAAA']
    if all_ips:
        logging.info(f"Performing Reverse DNS (PTR) lookups for IPs: {all_ips}")
        for ip in all_ips:
            try:
                addr = dns.reversename.from_address(ip)
                ptr_answers = resolver.resolve(addr, "PTR", raise_on_no_answer=False)
                if ptr_answers.rrset is None: records['PTR'][ip] = 'No PTR record found'
                else: records['PTR'][ip] = sorted([str(rdata) for rdata in ptr_answers])[0]
            except dns.resolver.NXDOMAIN: records['PTR'][ip] = 'No PTR record found (NXDOMAIN)'
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

    has_meaningful_data = any(
         k != 'PTR' and rec_list != ['No record found'] and not (isinstance(rec_list, list) and rec_list and rec_list[0].startswith('Error')) and not (isinstance(rec_list, list) and rec_list and rec_list[0].startswith('Query timed out'))
         for k, rec_list in records.items() if k != 'PTR'
    )
    if not has_meaningful_data and 'error' not in records:
        all_failed_or_timeout = all(
            (isinstance(rec_list, list) and rec_list and (rec_list[0].startswith('Query timed out') or rec_list[0].startswith('Error querying') or rec_list == ['No record found']))
            for k, rec_list in records.items() if k != 'PTR' and isinstance(rec_list, list) and rec_list
        )
        if all_failed_or_timeout:
             all_timed_out = all(rec_list[0].startswith('Query timed out') for k, rec_list in records.items() if k != 'PTR' and isinstance(rec_list, list) and rec_list and rec_list != ['No record found'])
             if all_timed_out:
                  return {'error': f'All DNS queries timed out (>{resolver.timeout}s). Network issue or target nameservers unreachable.'}
             else:
                  return {'warning': 'Most DNS queries failed or timed out using public resolvers.'}
        else: 
            return {'warning': 'Could not resolve any standard DNS records meaningfully.'}

    if 'TXT' in records and isinstance(records['TXT'], list):
        records['SPF'] = [r for r in records['TXT'] if r.lower().startswith('"v=spf1')]
        records['DMARC'] = [r for r in records['TXT'] if r.lower().startswith('"v=dmarc1')]
        records['DKIM_Note'] = "DKIM records usually exist at selector._domainkey subdomain (e.g., google._domainkey.domain.com) and require separate lookups."
        if not records['SPF']: records['SPF'] = ["No SPF record found"]
        if not records['DMARC']: records['DMARC'] = ["No DMARC record found"]
    return records

def get_whois_info(domain):
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
            'domain_name': clean_data(w.domain_name), 'registrar': w.registrar or 'Not specified',
            'creation_date': format_date(w.creation_date), 'expiration_date': format_date(w.expiration_date),
            'last_updated': format_date(w.updated_date), 'name_servers': clean_data(w.name_servers),
            'status': clean_data(w.status), 'emails': clean_data(w.emails),
            'dnssec': w.dnssec or 'Not specified', 'owner': clean_data(w.name), 'org': clean_data(w.org),
            'address': clean_data(w.address), 'city': clean_data(w.city),
            'state': clean_data(w.state), 'zipcode': clean_data(w.zipcode), 'country': clean_data(w.country),
        }
    except whois.exceptions.UnknownTld:
         logging.warning(f"WHOIS lookup failed for {domain}: Unknown TLD")
         return {'error': f'WHOIS lookup failed: Unknown TLD for domain "{domain}"'}
    except whois.exceptions.WhoisCommandFailed as e:
         logging.error(f"WHOIS command failed for {domain}: {e}", exc_info=True)
         return {'error': f'WHOIS lookup failed: Server communication problem or command issue.'}
    except whois.exceptions.WhoisPrivateRegistry:
        logging.warning(f"WHOIS lookup for {domain} indicates a private registry.")
        return {'warning': f'WHOIS information may be limited: Registry for this TLD is private.'}
    except Exception as e:
        logging.error(f"Unexpected error in get_whois_info for {domain}: {e}", exc_info=True)
        return {'error': f'WHOIS lookup failed: An unexpected error occurred ({type(e).__name__})'}

# --- Subdomain Functions ---
def query_crtsh(domain):
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
    all_subdomains = set()
    results_log = {'crtsh': 'Not Run', 'sublist3r': 'Disabled'}
    errors = []
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

# --- SMTP Check Functions ---
def check_smtp_server(server_ip, server_hostname, domain):
    result = {'status': 'Not Run', 'banner': None, 'connect_time_ms': None, 'errors': []}
    smtp_port = 25
    start_time = time.time()
    try:
        logging.info(f"Attempting SMTP connection to {server_hostname} ({server_ip}) on port {smtp_port}")
        with smtplib.SMTP(server_ip, smtp_port, timeout=10) as server:
            result['connect_time_ms'] = round((time.time() - start_time) * 1000)
            result['banner'] = server.getwelcome().strip()
            logging.info(f"SMTP connected to {server_hostname}, banner: {result['banner']}")
            try:
                 helo_resp_code, helo_resp_msg_bytes = server.helo(f"check.{domain}")
                 helo_resp_msg = helo_resp_msg_bytes.decode(errors='ignore')
                 if helo_resp_code != 250:
                      result['errors'].append(f"HELO command failed: {helo_resp_code} {helo_resp_msg}")
                 else:
                      logging.info(f"HELO command successful on {server_hostname}")
            except Exception as helo_e:
                 result['errors'].append(f"Error during HELO: {type(helo_e).__name__}")
                 logging.warning(f"HELO command error on {server_hostname}: {helo_e}")
            result['status'] = 'Success'
    except smtplib.SMTPConnectError as e:
        result['status'] = 'Failed (Connection Error)'; result['errors'].append(f"Connection Error: {e}")
        logging.warning(f"SMTP connection error to {server_hostname}: {e}")
    except smtplib.SMTPHeloError as e:
        result['status'] = 'Failed (HELO Error)'; result['errors'].append(f"HELO Error: {e}")
        logging.warning(f"SMTP HELO error on {server_hostname}: {e}")
    except smtplib.SMTPServerDisconnected as e:
        result['status'] = 'Failed (Disconnected)'; result['errors'].append(f"Server disconnected unexpectedly: {e}")
        logging.warning(f"SMTP server disconnected {server_hostname}: {e}")
    except socket.timeout:
        result['status'] = 'Failed (Timeout)'; result['errors'].append("Connection or command timed out (>10s)")
        logging.warning(f"SMTP timeout connecting/communicating with {server_hostname}")
    except socket.error as e:
        result['status'] = 'Failed (Socket Error)'; result['errors'].append(f"Socket Error: {e}")
        logging.warning(f"SMTP socket error for {server_hostname}: {e}")
    except Exception as e:
        result['status'] = 'Failed (Unexpected Error)'; result['errors'].append(f"Unexpected Error: {type(e).__name__} - {e}")
        logging.error(f"Unexpected SMTP error for {server_hostname}: {e}", exc_info=True)
    if not result['errors']: result['errors'] = ["No errors encountered during basic SMTP check."]
    return result

def get_smtp_diagnostics(domain, dns_results):
    smtp_results = {}
    mx_records = dns_results.get('MX', [])
    resolver = dns.resolver.Resolver(); resolver.timeout = 5; resolver.lifetime = 5
    if not mx_records or mx_records == ['No record found']:
        return {'info': 'No MX records found to perform SMTP checks.'}
    mail_servers = []
    for record in mx_records:
        parts = record.split()
        if len(parts) == 2:
            try:
                preference = int(parts[0]); hostname = parts[1].rstrip('.')
                mail_servers.append({'preference': preference, 'hostname': hostname})
            except ValueError: logging.warning(f"Could not parse MX record: {record}")
        else: logging.warning(f"Could not parse MX record: {record}")
    if not mail_servers: return {'error': 'Could not parse any valid MX hostnames.'}
    mail_servers.sort(key=lambda x: x['preference'])
    logging.info(f"Found MX servers to check: {mail_servers}")
    for server_info in mail_servers:
        hostname = server_info['hostname']
        server_ips = []; errors = []
        try:
            a_answers = resolver.resolve(hostname, 'A', raise_on_no_answer=False)
            if a_answers.rrset: server_ips.extend([str(rdata) for rdata in a_answers])
        except Exception as e: errors.append(f"A record lookup failed for {hostname}: {type(e).__name__}")
        try:
             aaaa_answers = resolver.resolve(hostname, 'AAAA', raise_on_no_answer=False)
             if aaaa_answers.rrset: server_ips.extend([str(rdata) for rdata in aaaa_answers])
        except Exception as e: errors.append(f"AAAA record lookup failed for {hostname}: {type(e).__name__}")
        
        result_key = f"{hostname} (Pref {server_info['preference']})"
        if not server_ips:
            smtp_results[result_key] = {'status': 'Failed (Hostname Resolution)', 'errors': errors or ["Could not resolve hostname to any IP address."]}
            continue
        first_ip = server_ips[0]
        logging.info(f"Checking SMTP for {hostname} at IP {first_ip}")
        smtp_check_result = check_smtp_server(first_ip, hostname, domain)
        smtp_results[result_key] = smtp_check_result
    return smtp_results

# --- Blacklist Check Functions ---
def check_ip_dnsbl(ip, dnsbl_server, resolver):
    try:
        if ':' in ip: 
             logging.warning(f"IPv6 DNSBL check for {ip} on {dnsbl_server} is using a placeholder reversal and might not be accurate.")
             return dnsbl_server, "IPv6 Not Supported Yet" 
        else: # IPv4
            rev_ip = ".".join(reversed(ip.split('.'))) + "." + dnsbl_server
        logging.info(f"Checking DNSBL {dnsbl_server} for {ip} via {rev_ip}")
        resolver.resolve(rev_ip, 'A')
        logging.warning(f"IP {ip} IS LISTED on {dnsbl_server}")
        return dnsbl_server, True
    except dns.resolver.NXDOMAIN:
        logging.info(f"IP {ip} not listed on {dnsbl_server}")
        return dnsbl_server, False
    except dns.resolver.Timeout:
        logging.warning(f"DNSBL check timed out for {ip} on {dnsbl_server}")
        return dnsbl_server, "Timeout"
    except Exception as e:
        logging.error(f"Error checking DNSBL {dnsbl_server} for {ip}: {e}")
        return dnsbl_server, f"Error ({type(e).__name__})"

def get_blacklist_checks(domain, dns_results):
    blacklist_results = {'summary': {}, 'details': {}}
    ips_to_check = set()
    if isinstance(dns_results.get('A'), list): ips_to_check.update(ip for ip in dns_results['A'] if '.' in ip)
    if isinstance(dns_results.get('AAAA'), list): ips_to_check.update(ip for ip in dns_results['AAAA'] if ':' in ip)
    mx_records = dns_results.get('MX', [])
    resolver = dns.resolver.Resolver(); resolver.timeout = 5; resolver.lifetime = 5
    if isinstance(mx_records, list) and mx_records != ['No record found']:
         for record in mx_records:
             parts = record.split()
             if len(parts) == 2:
                 hostname = parts[1].rstrip('.')
                 try:
                     a_answers = resolver.resolve(hostname, 'A', raise_on_no_answer=False)
                     if a_answers.rrset: ips_to_check.update(str(rdata) for rdata in a_answers)
                 except Exception: pass
                 try:
                      aaaa_answers = resolver.resolve(hostname, 'AAAA', raise_on_no_answer=False)
                      if aaaa_answers.rrset: ips_to_check.update(str(rdata) for rdata in aaaa_answers)
                 except Exception: pass
    if not ips_to_check:
        return {'info': 'No IPs found (A/AAAA/MX) to check against blacklists.'}
    logging.info(f"Checking IPs against DNSBLs: {list(ips_to_check)}")
    dnsbl_resolver = dns.resolver.Resolver()
    dnsbl_resolver.nameservers = ['1.1.1.1', '8.8.8.8']; dnsbl_resolver.timeout = 5; dnsbl_resolver.lifetime = 5
    listed_count, error_count, timeout_count, ipv6_unsupported_count = 0, 0, 0, 0
    max_workers = 10
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for ip in ips_to_check:
            blacklist_results['details'][ip] = {}
            for dnsbl in DNSBL_LIST:
                 future = executor.submit(check_ip_dnsbl, ip, dnsbl, dnsbl_resolver)
                 futures[future] = (ip, dnsbl)
        for future in as_completed(futures):
            ip, dnsbl = futures[future]
            try:
                dnsbl_server_returned, result = future.result()
                blacklist_results['details'][ip][dnsbl_server_returned] = result
                if result is True: listed_count += 1
                elif result == "Timeout": timeout_count += 1
                elif result == "IPv6 Not Supported Yet": ipv6_unsupported_count +=1
                elif isinstance(result, str) and "Error" in result: error_count += 1
            except Exception as exc:
                logging.error(f"Exception getting result for DNSBL check ({ip} on {dnsbl}): {exc}")
                blacklist_results['details'][ip][dnsbl] = f"Execution Error ({type(exc).__name__})"
                error_count += 1
    blacklist_results['summary'] = {
        'ips_checked': len(ips_to_check), 'blacklists_queried_per_ipv4': len(DNSBL_LIST),
        'listings_found': listed_count, 'timeouts': timeout_count, 'errors': error_count,
        'ipv6_checks_skipped_unsupported': ipv6_unsupported_count
    }
    logging.info(f"Blacklist check summary: {blacklist_results['summary']}")
    return blacklist_results

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
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
        if ':' in domain: domain = domain.split(':')[0]
        if not domain:
             logging.error(f"Could not extract domain from validated URL: {full_url}")
             return jsonify({'error': 'Could not extract domain from URL'}), 400

        logging.info(f"--- Starting Comprehensive Scan for Domain: {domain} ---")
        scan_results = {
            'target_url': full_url, 'target_domain': domain,
            'metadata': None, 'security_headers': None, 'dns_records': None, 'whois': None,
            'smtp_diagnostics': None, 'blacklist_checks': None, 'subdomains': None,
        }

        # 1. DNS Records
        logging.info(f"Step 1: Performing DNS lookups for {domain}")
        dns_results = get_dns_records(domain)
        scan_results['dns_records'] = dns_results
        if isinstance(dns_results, dict) and 'error' in dns_results and dns_results['error'].endswith('(NXDOMAIN)'):
             logging.error(f"Scan aborted for {domain}: Domain does not exist (NXDOMAIN).")
             return jsonify(scan_results)
        
        dns_had_critical_error = isinstance(dns_results, dict) and 'error' in dns_results

        # 2. WHOIS
        logging.info(f"Step 2: Performing WHOIS lookup for {domain}")
        scan_results['whois'] = get_whois_info(domain)

        # 3. Subdomains
        logging.info(f"Step 3: Performing Subdomain lookup for {domain}")
        scan_results['subdomains'] = get_subdomains(domain)

        # 4. Metadata & Security Headers
        logging.info(f"Step 4: Performing Metadata & Security Header check for {full_url}")
        metadata_result = get_metadata(full_url)
        scan_results['metadata'] = metadata_result
        if isinstance(metadata_result, dict) and not metadata_result.get('error') and metadata_result.get('headers'):
            scan_results['security_headers'] = check_security_headers(metadata_result['headers'])
        elif isinstance(metadata_result, dict) and metadata_result.get('error'):
             scan_results['security_headers'] = {'info': f"Skipped due to metadata retrieval error: {metadata_result.get('error')}"}
        else:
            scan_results['security_headers'] = {'info': 'Skipped due to missing headers in metadata or other metadata issue.'}

        # 5. SMTP Diagnostics
        logging.info(f"Step 5: Performing SMTP diagnostics for {domain}")
        if not dns_had_critical_error:
             scan_results['smtp_diagnostics'] = get_smtp_diagnostics(domain, dns_results)
        else:
             scan_results['smtp_diagnostics'] = {'info': 'Skipped due to critical DNS errors.'}

        # 6. Blacklist Checks
        logging.info(f"Step 6: Performing Blacklist checks for {domain}")
        if not dns_had_critical_error:
             scan_results['blacklist_checks'] = get_blacklist_checks(domain, dns_results)
        else:
             scan_results['blacklist_checks'] = {'info': 'Skipped due to critical DNS errors.'}

        logging.info(f"--- Comprehensive Scan Completed for Domain: {domain} ---")
        return jsonify(scan_results)

    except Exception as e:
        logging.error(f"Critical error during scan orchestration for {url_input}: {e}", exc_info=True)
        return jsonify({'error': f'An unexpected server error occurred during the scan orchestration: {type(e).__name__}'}), 500

# --- Main Execution ---
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
