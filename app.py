# app.py
import os
import logging
import re
import json
import socket
import time
from urllib.parse import urlparse, urljoin

# Installed Libraries (Ensure these are installed via pip later)
import requests
from bs4 import BeautifulSoup
import dns.resolver
import whois
from ipwhois import IPWhois
from dateutil.parser import parse as parse_date
from flask import Flask, request, jsonify, render_template

# Use builtwith for technology detection
try:
    import builtwith
except ImportError:
    builtwith = None
    logging.warning("[Warning] 'builtwith' library not found. Run 'pip install builtwith'. Technology/E-commerce detection will be limited.")

# --- Configuration ---
logging.getLogger("whois").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.WARNING) # Suppress InsecureRequestWarning when verify=False
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Flask App Initialization ---
# Make sure CloudPanel knows where to find the templates folder
app = Flask(__name__, template_folder='templates')

# --- Helper Functions ---

def get_ip_details(ip_address):
    """ Gets details for a given IP address using socket and ipwhois. """
    details = { 'ip': ip_address, 'hostname': 'N/A', 'isp': 'N/A', 'asn_description': 'N/A', 'potentially_shared': False, 'ip_range': 'N/A', 'ip_name': 'N/A' }
    try:
        details['hostname'] = socket.gethostbyaddr(ip_address)[0]
        generic_patterns = ['shared', 'server', 'host', 'vps', 'dedi', 'cloud', 'hosting']
        if any(pat in details['hostname'].lower() for pat in generic_patterns) and ip_address not in details['hostname']: details['potentially_shared'] = True
    except (socket.herror, socket.gaierror) as e: logging.warning(f"rDNS failed {ip_address}: {e}"); details['hostname'] = "Lookup Failed"
    except Exception as e: logging.error(f"rDNS unexpected error {ip_address}: {e}")
    try:
        obj = IPWhois(ip_address); ipwhois_results = obj.lookup_rdap(depth=1)
        details['isp'] = ipwhois_results.get('asn_description', 'N/A')
        details['asn_description'] = ipwhois_results.get('asn_description', 'N/A')
        network_info = ipwhois_results.get('network', {});
        if network_info: details['ip_range'] = network_info.get('cidr', 'N/A'); details['ip_name'] = network_info.get('name', 'N/A')
    except Exception as e: logging.error(f"IPWhois failed {ip_address}: {e}"); details['isp'] = "ISP Lookup Error"; details['asn_description'] = "ASN Lookup Error"
    return details

def detect_cms_and_ecommerce(domain, soup):
    """ Performs basic CMS and E-commerce detection from pre-fetched soup object. """
    detected_cms = "Unknown"; detected_ecom = None
    if not soup: return detected_cms, detected_ecom
    try:
        content_start_decoded = str(soup).lower()
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            generator_content = meta_generator.get('content').lower()
            if 'wordpress' in generator_content: detected_cms = 'WordPress'
            elif 'joomla' in generator_content: detected_cms = 'Joomla!'
            elif 'drupal' in generator_content: detected_cms = 'Drupal'
            elif 'wix' in generator_content: detected_cms = 'Wix'; detected_ecom = 'Wix Stores'
            elif 'squarespace' in generator_content: detected_cms = 'Squarespace'; detected_ecom = 'Squarespace Commerce'
            elif 'shopify' in generator_content: detected_cms = 'Shopify'; detected_ecom = 'Shopify'
            elif 'prestashop' in generator_content: detected_cms = 'PrestaShop'; detected_ecom = 'PrestaShop'
            elif 'typo3' in generator_content: detected_cms = 'TYPO3 CMS'
            elif 'bigcommerce' in generator_content: detected_cms = 'BigCommerce'; detected_ecom = 'BigCommerce'
            elif 'magento' in generator_content: detected_cms = 'Magento'; detected_ecom = 'Magento'

        if ('wp-content' in content_start_decoded or 'wp-includes' in content_start_decoded):
            detected_cms = 'WordPress'
            if 'woocommerce' in content_start_decoded or 'wp-content/plugins/woocommerce' in content_start_decoded: detected_ecom = 'WooCommerce'
        elif ('sites/all/modules' in content_start_decoded or '/drupal.js' in content_start_decoded): detected_cms = 'Drupal'
        elif ('com_content' in content_start_decoded or '/media/jui/' in content_start_decoded): detected_cms = 'Joomla!'
        elif ('static.parastorage.com' in content_start_decoded or 'wix.' in content_start_decoded): detected_cms = 'Wix'; detected_ecom = detected_ecom or 'Wix Stores'
        elif ('squarespace.' in content_start_decoded): detected_cms = 'Squarespace'; detected_ecom = detected_ecom or 'Squarespace Commerce'
        elif ('cdn.shopify.com' in content_start_decoded or 'shopify.' in content_start_decoded): detected_cms = 'Shopify'; detected_ecom = detected_ecom or 'Shopify'
        elif ('prestashop' in content_start_decoded or '/themes/prestashop/' in content_start_decoded): detected_cms = 'PrestaShop'; detected_ecom = detected_ecom or 'PrestaShop'
        elif ('/media/magento/' in content_start_decoded or 'magento/requirejs' in content_start_decoded): detected_cms = 'Magento'; detected_ecom = detected_ecom or 'Magento'
        elif ('cdn*.bigcommerce.com' in content_start_decoded or 'bigcommerce.' in content_start_decoded): detected_cms = 'BigCommerce'; detected_ecom = detected_ecom or 'BigCommerce'

        if not detected_ecom:
            if any(path in content_start_decoded for path in ['/checkout', '/cart', '/basket', 'add_to_cart', 'add-to-basket']): detected_ecom = "Likely E-commerce (Cart/Checkout Found)"
            elif any(script in content_start_decoded for script in ['stripe.js', 'paypal.com/sdk/js', 'braintreegateway.com']): detected_ecom = "Likely E-commerce (Payment Script Found)"
    except Exception as e: logging.error(f"Error basic CMS/Ecom detect {domain}: {e}")
    return detected_cms, detected_ecom

def prepare_url(domain):
    """ Tries to create a fetchable URL & get initial headers, preferring HTTPS. """
    domain = domain.lower().strip(); headers = {'User-Agent': 'WebyverseDomainIntel/1.0', 'Accept-Language':'en-US,en;q=0.5'}; last_successful_headers = None; final_url_to_return = None; scheme_provided = re.match(r'^https?\:\/\/.*', domain);
    if not scheme_provided:
        url_https = f"https://{domain}";
        try: response = requests.head(url_https, timeout=5, allow_redirects=True, verify=False, headers=headers); response.raise_for_status(); final_url = response.url; parsed_final = urlparse(final_url);
             if parsed_final.netloc.endswith(domain): logging.info(f"Prepared URL (HTTPS HEAD): {final_url}"); final_url_to_return = final_url; last_successful_headers = response.headers
             else: logging.warning(f"HTTPS {domain} redirected off-domain: {final_url}. Trying HTTP.")
        except requests.exceptions.RequestException as e_head_https: logging.warning(f"HTTPS HEAD failed for {domain}: {e_head_https}. Trying GET.");
             try: response = requests.get(url_https, timeout=7, allow_redirects=True, verify=False, headers=headers, stream=True); response.raise_for_status(); final_url = response.url; parsed_final = urlparse(final_url);
                  if parsed_final.netloc.endswith(domain): logging.info(f"Prepared URL (HTTPS GET): {final_url}"); final_url_to_return = final_url; last_successful_headers = response.headers
                  else: logging.warning(f"HTTPS GET {domain} redirected off-domain: {final_url}. Trying HTTP.");
                  response.close()
             except requests.exceptions.RequestException as e_get_https: logging.warning(f"HTTPS GET also failed for {domain}: {e_get_https}. Trying HTTP.")
        if not final_url_to_return:
            url_http = f"http://{domain}";
            try: response = requests.head(url_http, timeout=5, allow_redirects=True, headers=headers); response.raise_for_status(); final_url = response.url; parsed_final = urlparse(final_url);
                 if parsed_final.netloc.endswith(domain): logging.info(f"Prepared URL (HTTP HEAD): {final_url}"); final_url_to_return = final_url; last_successful_headers = response.headers
                 else: logging.warning(f"HTTP {domain} redirected off-domain: {final_url}.")
            except requests.exceptions.RequestException as e_head_http: logging.warning(f"HTTP HEAD failed for {domain}: {e_head_http}. Trying GET.");
                 try: response = requests.get(url_http, timeout=7, allow_redirects=True, headers=headers, stream=True); response.raise_for_status(); final_url = response.url; parsed_final = urlparse(final_url);
                      if parsed_final.netloc.endswith(domain): logging.info(f"Prepared URL (HTTP GET): {final_url}"); final_url_to_return = final_url; last_successful_headers = response.headers
                      else: logging.warning(f"HTTP GET {domain} redirected off-domain: {final_url}.");
                      response.close()
                 except requests.exceptions.RequestException as e_get_http: logging.warning(f"HTTP GET also failed for {domain}: {e_get_http}.")
    else: logging.info(f"Scheme provided for {domain}, attempting validation...");
        try: response = requests.head(domain, timeout=5, allow_redirects=True, verify=False, headers=headers); response.raise_for_status(); final_url_to_return = response.url; last_successful_headers = response.headers; logging.info(f"Validated provided URL (HEAD): {final_url_to_return}")
        except requests.exceptions.RequestException as e_head_provided: logging.warning(f"Provided URL HEAD failed for {domain}: {e_head_provided}. Trying GET.");
             try: response = requests.get(domain, timeout=7, allow_redirects=True, verify=False, headers=headers, stream=True); response.raise_for_status(); final_url_to_return = response.url; last_successful_headers = response.headers; logging.info(f"Validated provided URL (GET): {final_url_to_return}"); response.close()
             except requests.exceptions.RequestException as e_get_provided: logging.warning(f"Provided URL GET also failed for {domain}: {e_get_provided}.")
    if not final_url_to_return: logging.error(f"Could not prepare a working URL for {domain}")
    return final_url_to_return, last_successful_headers

def get_builtwith_info(url):
    """ Detects technologies using the builtwith library. """
    if not builtwith: return {"error": "Builtwith library not available."}
    if not url: return {"error": "Valid URL required for Builtwith check."}
    logging.info(f"Running Builtwith on {url}")
    try: tech_info = builtwith.parse(url); logging.info(f"Builtwith detected {len(tech_info)} tech categories for {url}"); return tech_info if tech_info else {"info": "No technologies identified by Builtwith."}
    except Exception as e: logging.error(f"Builtwith check failed for {url}: {e}"); return {"error": f"Builtwith failed: {type(e).__name__}"}

def check_robots_sitemap(domain):
    """ Checks for robots.txt and sitemap.xml. """
    results = {"robots_txt_exists": False, "sitemap_xml_exists": False, "sitemap_urls": []}; domain = domain.lower().strip(); headers = {'User-Agent': 'WebyverseDomainIntel/1.0'}; robots_url = f"http://{domain}/robots.txt";
    logging.info(f"Checking robots.txt at {robots_url}");
    try: response = requests.get(robots_url, timeout=5, headers=headers, allow_redirects=False);
         if response.status_code == 200 and '<html>' not in response.text.lower():
            results["robots_txt_exists"] = True; logging.info(f"Found robots.txt for {domain}"); sitemap_pattern = re.compile(r'^\s*Sitemap:\s*(.*)', re.IGNORECASE | re.MULTILINE); found_sitemaps = sitemap_pattern.findall(response.text);
            if found_sitemaps: results["sitemap_urls"].extend([s.strip() for s in found_sitemaps]); results["sitemap_xml_exists"] = True; logging.info(f"Found sitemap(s) in robots.txt: {results['sitemap_urls']}")
         elif 200 <= response.status_code < 300: results["robots_txt_exists"] = False
         else: logging.warning(f"robots.txt check for {domain} status {response.status_code}")
    except requests.exceptions.RequestException as e: logging.warning(f"Could not fetch robots.txt for {domain}: {e}")
    if not results["sitemap_xml_exists"]:
        logging.info(f"Checking common sitemap locations for {domain}"); sitemap_locations = [ f"https://{domain}/sitemap.xml", f"https://{domain}/sitemap_index.xml", f"http://{domain}/sitemap.xml", f"http://{domain}/sitemap_index.xml" ];
        for sitemap_url in sitemap_locations:
            try: response = requests.head(sitemap_url, timeout=5, headers=headers, verify=False, allow_redirects=True);
                 if response.status_code == 200: results["sitemap_xml_exists"] = True; final_sitemap_url = response.url;
                 if final_sitemap_url not in results["sitemap_urls"]: results["sitemap_urls"].append(final_sitemap_url); logging.info(f"Found sitemap via direct check: {final_sitemap_url}"); break
            except requests.exceptions.RequestException: pass
    return results

def check_security_headers(url, headers_obj=None):
    """ Checks common security headers. """
    if not url and not headers_obj: logging.warning("check_security_headers needs URL or headers_obj."); return {"error": "URL or Headers object required."}
    headers_to_check = [ 'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy' ]; found_headers = {}; response_headers_lower = {};
    if headers_obj: logging.info(f"Checking provided security headers for {url or 'source'}");
        try: response_headers_lower = {k.lower(): v for k, v in headers_obj.items()}
        except AttributeError: logging.error("Invalid headers_obj provided."); return {"error": "Invalid headers object."}
    elif url: logging.info(f"Fetching security headers for {url}");
        try: response = requests.get(url,timeout=7,allow_redirects=True,headers={'User-Agent': 'WebyverseDomainIntel/1.0'},verify=False); response.raise_for_status(); response_headers_lower = {k.lower(): v for k, v in response.headers.items()}; logging.debug(f"Fetched headers for {url}")
        except requests.exceptions.RequestException as e: logging.error(f"Could not fetch headers from {url}: {e}"); return {"error": f"Could not fetch URL: {type(e).__name__}"}
    for header in headers_to_check: found_headers[header] = response_headers_lower.get(header.lower(), None)
    found_count = sum(1 for v in found_headers.values() if v is not None); summary = f"{found_count}/{len(headers_to_check)} common headers found." if found_count > 0 else "No common security headers found."; found_headers["summary"] = summary; logging.info(f"Security headers check complete. {summary}");
    return found_headers

def scrape_contact_info(url):
    """ Scrapes a URL for social media links and potential emails. """
    if not url: return {"social_links": [], "emails": []}; social_patterns = { 'LinkedIn': r'linkedin\.com/(?:company|in|pub)/', 'Twitter': r'twitter\.com/|x\.com/', 'Facebook': r'facebook\.com/', 'Instagram': r'instagram\.com/', 'YouTube': r'youtube\.com/|youtu\.be/', 'GitHub': r'github\.com/' }; found_social_links = {}; found_emails = set(); headers = {'User-Agent': 'WebyverseDomainIntel/1.0', 'Accept-Language': 'en-US,en;q=0.9'}; logging.info(f"Scraping contact info from {url}");
    try:
        response = requests.get(url, timeout=7, headers=headers, verify=False); response.raise_for_status(); soup = BeautifulSoup(response.content, 'html.parser'); email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}');
        for a_tag in soup.find_all('a', href=lambda href: href and href.lower().startswith('mailto:')):
            email_match = email_regex.search(a_tag['href']);
            if email_match: found_emails.add(email_match.group(0).lower())
        text_content = "";
        for element in soup.find_all(['p', 'div', 'span', 'li', 'footer', 'address', 'a']): text_content += element.get_text(separator=' ') + " "
        potential_emails = email_regex.findall(text_content);
        for email in potential_emails:
            if not any(x in email for x in ['@example.com','@domain.com','sentry.io','.png','.jpeg','.jpg','.gif','.webp','wixpress.']) and len(email.split('@')[0]) > 1 : found_emails.add(email.lower())
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'];
            if not href or href.startswith(('#', 'javascript:', 'tel:')): continue
            try: absolute_href = urljoin(url, href)
            except ValueError: continue
            parsed_link = urlparse(absolute_href);
            if not parsed_link.scheme in ['http', 'https'] or not parsed_link.netloc: continue
            for platform, pattern in social_patterns.items():
                 if re.search(pattern, absolute_href, re.IGNORECASE):
                     if platform not in found_social_links: cleaned_link = absolute_href.split('?')[0].split('#')[0]; found_social_links[platform] = cleaned_link
                     break
        logging.info(f"Found {len(found_social_links)} platforms, {len(found_emails)} potential emails on {url}")
    except requests.exceptions.RequestException as e: logging.error(f"Could not fetch/parse {url} for contact: {e}"); return {"error": f"Could not fetch URL: {type(e).__name__}", "social_links": [], "emails": []}
    except Exception as e: logging.error(f"Error parsing HTML for contact on {url}: {e}"); return {"error": f"HTML Parsing Error: {type(e).__name__}", "social_links": [], "emails": []}
    return { "social_links": list(found_social_links.values()), "emails": sorted(list(found_emails)) }

def get_archive_info(domain):
     """ Gets first and last captures from Archive.org. """
     if not domain: return None; domain = domain.lower().strip(); results = {"first_capture": None, "last_capture": None}; earliest_ts = None; latest_ts = None; logging.info(f"Checking Archive.org for {domain}"); urls_to_check = [domain];
     if not domain.startswith("www."): urls_to_check.append(f"www.{domain}")
     headers = {'User-Agent': 'WebyverseDomainIntel/1.0'};
     for target_url in urls_to_check:
         cdx_url = f"https://web.archive.org/cdx/search/cdx?url={target_url}&output=json&fl=timestamp&statuscode=200&limit=1&sort=";
         try:
             response_first = requests.get(cdx_url + "asc", timeout=10, headers=headers); time.sleep(0.3); response_last = requests.get(cdx_url + "desc", timeout=10, headers=headers);
             if response_first.status_code == 200:
                 data_first = response_first.json();
                 if len(data_first) > 1 and len(data_first[1]) > 0: ts=data_first[1][0];
                 if earliest_ts is None or ts < earliest_ts: earliest_ts = ts
             if response_last.status_code == 200:
                 data_last = response_last.json();
                 if len(data_last) > 1 and len(data_last[1]) > 0: ts=data_last[1][0];
                 if latest_ts is None or ts > latest_ts: latest_ts = ts
         except requests.exceptions.RequestException as e: logging.error(f"Error connecting Archive.org {target_url}: {e}")
         except json.JSONDecodeError as e: logging.error(f"Error decoding Archive.org JSON {target_url}: {e}")
         except Exception as e: logging.error(f"Unexpected error archive info {target_url}: {e}")
         if earliest_ts and latest_ts and target_url == domain : break # Prioritize root domain if successful
         time.sleep(0.3) # Be polite between www/non-www checks
     if earliest_ts: try: results["first_capture"] = parse_date(earliest_ts).strftime('%Y-%m-%d') except: results["first_capture"] = earliest_ts
     if latest_ts: try: results["last_capture"] = parse_date(latest_ts).strftime('%Y-%m-%d') except: results["last_capture"] = latest_ts
     if results["first_capture"] or results["last_capture"]: logging.info(f"Archive info found for {domain}: {results}"); return results
     else: logging.info(f"No Archive.org info found for {domain}"); return {"info": "No successful captures found on Archive.org."}


# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the main HTML page."""
    # Make sure index.html is in the 'templates' folder relative to app.py
    return render_template('index.html')


# --- FINAL /analyze Route ---
@app.route('/analyze', methods=['POST'])
def analyze():
    """ Handles the domain analysis request using updated libraries. """
    domain = request.form.get('domain')
    if not domain: return jsonify({'error': 'Domain name is required'}), 400

    # Domain Cleaning
    parsed_uri = urlparse(f'//{domain}' if '//' not in domain else domain)
    domain = parsed_uri.netloc or parsed_uri.path; domain = domain.split(':')[0]; domain = domain.strip('/').lower()
    if not domain or '.' not in domain or len(domain.split('.')[-1]) < 2: logging.error(f"Invalid domain format: {request.form.get('domain')} -> {domain}"); return jsonify({'error': 'Invalid domain name format'}), 400

    logging.info(f"Starting analysis for domain: {domain}")
    results = {
        'domain': domain, 'whois': None, 'dns': {}, 'nameservers': None, 'email_provider': None,
        'ip_info': [], 'hosting_provider': "Unknown", 'hosting_type': 'Unknown',
        'hosting_type_note': None, 'cms': "Unknown", 'web_server': None,
        'potential_revenue': "N/A - Requires paid APIs/private data.",
        'estimated_storage': "N/A - Cannot be determined.",
        'builtwith_info': None, 'ecommerce_platform': "Unknown",
        'robots_sitemap': None, 'security_headers': None,
        'contact_info': None, 'archive_info': None, 'error': None
    }

    # Prepare Base URL & Get Initial Headers/Content
    base_url, initial_headers = prepare_url(domain)
    initial_soup = None
    if base_url:
        results['web_server'] = next((v for k, v in initial_headers.items() if k.lower() == 'server'), None) if initial_headers else None
        try:
             fetch_headers = {'User-Agent': 'WebyverseDomainIntel/1.0', 'Accept-Language':'en-US,en;q=0.5'}
             page_response = requests.get(base_url, headers=fetch_headers, timeout=10, verify=False)
             page_response.raise_for_status()
             initial_soup = BeautifulSoup(page_response.content, 'html.parser') # Use built-in parser
        except requests.exceptions.RequestException as e: logging.warning(f"Could not fetch content from {base_url} for initial soup: {e}")

    # 1. WHOIS Lookup
    try:
        w = whois.whois(domain)
        if w and w.get('domain_name'): results['whois'] = {k: (v.isoformat() if hasattr(v, 'isoformat') else ([item.isoformat() if hasattr(item, 'isoformat') else item for item in v] if isinstance(v, list) else v)) for k, v in w.items() if v}
        else: results['whois'] = "WHOIS data not found or incomplete/redacted."; logging.warning(f"Incomplete/Redacted WHOIS for {domain}")
    except Exception as e: results['whois'] = f"Error: {type(e).__name__}"; logging.error(f"WHOIS fail {domain}: {e}")

    # 2. DNS Lookups
    resolver = dns.resolver.Resolver(); record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']; ip_addresses_ipv4 = []; ip_addresses_ipv6 = []; nxdomain_flag = False
    for rtype in record_types:
        try: answers = resolver.resolve(domain, rtype);
             if rtype == 'A': ip_addresses_ipv4 = [a.to_text() for a in answers]; results['dns']['A'] = ip_addresses_ipv4
             elif rtype == 'AAAA': ip_addresses_ipv6 = [a.to_text() for a in answers]; results['dns']['AAAA'] = ip_addresses_ipv6
             elif rtype == 'MX': mx_records = sorted([(mx.preference, mx.exchange.to_text().rstrip('.')) for mx in answers]); results['dns']['MX'] = [f"{p} {e}" for p,e in mx_records]; # Process provider later
             elif rtype == 'NS': ns_results = sorted([ns.target.to_text().rstrip('.') for ns in answers]); results['dns']['NS'] = ns_results; results['nameservers'] = ns_results
             elif rtype == 'TXT': txt_values=[b"".join(t.strings).decode('utf-8','replace').strip('"') for t in answers]; results['dns']['TXT']=sorted(txt_values)
             elif rtype == 'SOA': results['dns']['SOA'] = answers[0].to_text()
        except dns.resolver.NoAnswer: results['dns'][rtype] = "No record"
        except dns.resolver.NXDOMAIN: results['dns'][rtype]="NXDOMAIN"; nxdomain_flag=True; break
        except dns.exception.Timeout: results['dns'][rtype]="Timeout"; logging.warning(f"DNS timeout {domain}-{rtype}")
        except Exception as e: results['dns'][rtype]=f"Error:{type(e).__name__}"; logging.error(f"DNS fail {domain}-{rtype}: {e}")
    if nxdomain_flag: results['error'] = "NXDOMAIN"; results={k:v for k,v in results.items() if k in ['domain','whois','dns','error']}; logging.info(f"Stop NXDOMAIN {domain}."); return jsonify(results)
    # Determine Email Provider
    if 'MX' in results['dns'] and isinstance(results['dns']['MX'], list):
         if not results['dns']['MX']: results['email_provider'] = "No MX records found."
         else: mx_hosts=" ".join(mx.split(' ')[1].lower() for mx in results['dns']['MX']); # Rebuild here
         if 'google.com' in mx_hosts or 'googlemail.com' in mx_hosts: results['email_provider'] = 'Google Workspace / Gmail'
         elif 'outlook.com' in mx_hosts or 'protection.outlook.com' in mx_hosts: results['email_provider'] = 'Microsoft 365 / Outlook'
         elif 'zoho.' in mx_hosts: results['email_provider'] = 'Zoho Mail'
         else: results['email_provider'] = f"Likely: {results['dns']['MX'][0].split(' ')[1]}"
    elif 'MX' in results['dns']: results['email_provider'] = results['dns']['MX']
    else: results['email_provider'] = "MX Lookup Error"

    # 3. IP Info & Hosting
    all_ips = ip_addresses_ipv4 + ip_addresses_ipv6
    if all_ips: unique_ips = list(set(all_ips)); logging.info(f"Getting IP details {unique_ips[:3]}");
         for ip in unique_ips[:3]: try: results['ip_info'].append(get_ip_details(ip)) except Exception as e: logging.error(f"IP detail fail {ip}: {e}")
         if results['ip_info']: first_ip=results['ip_info'][0]; asn=first_ip.get('asn_description') or first_ip.get('isp');
         if asn and "Error" not in asn and asn != "N/A": results['hosting_provider'] = asn
    if results['hosting_provider'] == "Unknown" and results.get('nameservers'): ns_str = " ".join(results['nameservers']).lower();
         if 'cloudflare' in ns_str: results['hosting_provider'] = 'Cloudflare'
         elif 'awsdns' in ns_str or 'amazonaws.com' in ns_str: results['hosting_provider'] = 'Amazon AWS'
         elif 'google.com' in ns_str and 'domain' not in ns_str and 'googlemail' not in ns_str: results['hosting_provider'] = 'Google Cloud'
         elif 'google.com' in ns_str or 'googlemail.com' in ns_str: results['hosting_provider'] = 'Google Domains/Workspace'
         elif 'azure-dns' in ns_str: results['hosting_provider'] = 'Microsoft Azure'
         elif 'godaddy' in ns_str or 'domaincontrol' in ns_str: results['hosting_provider'] = 'GoDaddy'
         elif 'namecheap' in ns_str: results['hosting_provider'] = 'Namecheap'
         else: try: parts=results['nameservers'][0].split('.'); results['hosting_provider']=f"{parts[-2]}.{parts[-1]}" if len(parts)>=2 else results['nameservers'][0] except: pass

    # 4. Hosting Type Guess
    if results['ip_info']: results['hosting_type'] = 'Potentially Shared Hosting' if any(ip.get('potentially_shared') for ip in results['ip_info']) else 'Potentially Dedicated/VPS'
    results['hosting_type_note'] = "Detection based on rDNS patterns; not definitive."

    # 5. CMS & E-commerce Detection (Basic Scan using initial soup)
    results['cms'], ecom_basic = detect_cms_and_ecommerce(domain, initial_soup)
    if ecom_basic: results['ecommerce_platform'] = ecom_basic # Update if basic scan found

    # 6. Builtwith Technology Detection
    results['builtwith_info'] = get_builtwith_info(base_url)

    # 7. Refine E-commerce based on Builtwith
    if results['ecommerce_platform'] == "Unknown" or results['ecommerce_platform'] is None:
        if results['builtwith_info'] and isinstance(results['builtwith_info'], dict):
            ecom_platforms_builtwith = ['Shopify', 'WooCommerce', 'Magento', 'Bigcommerce', 'Prestashop', 'OpenCart', 'Ecwid', 'Volusion', 'VirtueMart', 'osCommerce']
            found_ecom = False; shop_tech = results['builtwith_info'].get('shop', [])
            for platform in ecom_platforms_builtwith:
                # Check case-insensitively
                if any(p.lower() == platform.lower() for p in shop_tech):
                     results['ecommerce_platform'] = platform; found_ecom = True; break
            if not found_ecom:
                 for category, tech_list in results['builtwith_info'].items():
                      if category in ['error','info']: continue
                      if isinstance(tech_list, list): # Ensure it's a list before iterating
                          for tech in tech_list:
                              if any(p.lower() == tech.lower() for p in ecom_platforms_builtwith):
                                   results['ecommerce_platform'] = tech # Use the name found in builtwith
                                   found_ecom = True; break
                      if found_ecom: break
            if found_ecom: logging.info(f"Detected e-com '{results['ecommerce_platform']}' via Builtwith.")

    # Final status for e-commerce if nothing detected
    if results['ecommerce_platform'] == "Unknown" or results['ecommerce_platform'] is None:
         results['ecommerce_platform'] = "Not Detected"

    # 8. Robots.txt & Sitemap
    results['robots_sitemap'] = check_robots_sitemap(domain)

    # 9. Security Headers
    results['security_headers'] = check_security_headers(base_url, initial_headers)

    # 10. Contact Info Scraping
    results['contact_info'] = scrape_contact_info(base_url)

    # 11. Archive.org Info
    results['archive_info'] = get_archive_info(domain)

    # Placeholders
    results['potential_revenue'] = "N/A - Requires paid APIs/private data."
    results['estimated_storage'] = "N/A - Cannot be determined."

    # Final Cleanup
    if results.get("error") is None: results.pop("error", None)

    logging.info(f"Analysis complete for domain: {domain}")
    return jsonify(results)


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    # Set debug=False for production!
    # If using Gunicorn, these host/port/debug values might be overridden anyway.
    app.run(debug=False, host='0.0.0.0', port=port)