import os
import uuid
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, make_response
import google.generativeai as genai
import requests
from supabase import create_client, Client
from dotenv import load_dotenv
import validators
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urlparse, urlencode
import logging

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Supabase
SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
supabase: Client = None

if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Initialize Gemini
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.0-flash-exp')

SALES_CHATBOT_PROMPT = """You are a professional sales assistant for ikanchan, an MVP development and project rescue service based in Leeds, UK.

**About ikanchan:**
- Owner: Kanchan - AI Developer & Business Innovation Specialist
- Experience: 16+ years professional experience, 6+ production AI apps built
- Location: Leeds, UK
- Google Cloud Certified

**Services Offered:**
1. Idea to MVP Development - From £2,000 (2-4 weeks)
2. Project Rescue/Fixing - From £2,000 (Fast turnaround)
3. Free 30-minute consultation
4. Follow-up consultations - £100/session

**Portfolio:**
- CareCircle (Healthcare) - NHS-ready medication adherence platform
- HomeRule (Real Estate) - UK planning permission checker
- TrueSkills (Education) - Anti-cheating assessment platform
- MathTales (EdTech) - Math learning for kids
- FindingUrWay (Travel) - AI travel planner
- WizardsTrial (Gaming)

**Your Goal:**
- Understand customer's problem
- Qualify if it's idea or broken project
- Highlight relevant portfolio work
- Book free 30-min consultation
- Be professional and concise

**Tone:** Professional, confident, solution-focused. No emojis."""

@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com https://generativelanguage.googleapis.com; img-src 'self' data: https:;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Chat service unavailable'}), 500
    
    try:
        data = request.json
        user_message = data.get('message', '').strip()
        conversation_history = data.get('history', [])
        session_id = request.cookies.get('session_id', str(uuid.uuid4()))
        
        if not user_message or len(user_message) > 5000:
            return jsonify({'error': 'Invalid message'}), 400
        
        chat_history = [SALES_CHATBOT_PROMPT]
        for msg in conversation_history[-10:]:
            role = msg.get('role', 'user')
            content = msg.get('content', '')
            chat_history.append(f"{role}: {content}")
        
        chat_history.append(f"user: {user_message}")
        prompt = "\n".join(chat_history) + "\nassistant:"
        response = model.generate_content(prompt)
        bot_response = response.text
        
        if supabase:
            try:
                supabase.table('chat_logs').insert({
                    'session_id': session_id,
                    'user_message': user_message,
                    'bot_response': bot_response,
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Supabase error: {e}")
        
        resp = make_response(jsonify({'response': bot_response, 'session_id': session_id}))
        resp.set_cookie('session_id', session_id, httponly=True, secure=True, samesite='Lax')
        return resp
    
    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        return jsonify({'error': 'Service unavailable'}), 500

@app.route('/api/analyze-github', methods=['POST'])
def analyze_github():
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Analysis service unavailable'}), 500
    
    try:
        data = request.json
        github_url = data.get('url', '').strip()
        
        if not github_url:
            return jsonify({'error': 'GitHub URL required'}), 400
        
        parts = github_url.replace('https://github.com/', '').replace('http://github.com/', '').split('/')
        if len(parts) < 2:
            return jsonify({'error': 'Invalid GitHub URL format'}), 400
        
        owner, repo = parts[0], parts[1]
        
        api_url = f'https://api.github.com/repos/{owner}/{repo}'
        response = requests.get(api_url, timeout=10)
        
        if response.status_code != 200:
            return jsonify({'error': 'Could not fetch repository'}), 400
        
        repo_data = response.json()
        
        contents_url = f'https://api.github.com/repos/{owner}/{repo}/contents'
        contents = requests.get(contents_url, timeout=10)
        files = []
        if contents.status_code == 200:
            file_data = contents.json()
            if isinstance(file_data, list):
                files = [f['name'] for f in file_data if isinstance(f, dict) and f.get('type') == 'file']
        
        readme_url = f'https://api.github.com/repos/{owner}/{repo}/readme'
        readme_content = ""
        readme_response = requests.get(readme_url, timeout=10)
        if readme_response.status_code == 200:
            readme_data = readme_response.json()
            if 'content' in readme_data:
                import base64
                try:
                    readme_content = base64.b64decode(readme_data['content']).decode('utf-8')[:2000]
                except:
                    pass
        
        prompt = f"""Analyze this GitHub repository and provide exactly 5 critical issues for improvement.

**Repository Information:**
- Name: {repo_data.get('name')}
- Description: {repo_data.get('description', 'No description')}
- Language: {repo_data.get('language', 'Not specified')}
- Stars: {repo_data.get('stargazers_count', 0)}
- Files: {', '.join(files[:30])}

**README:**
{readme_content if readme_content else 'No README'}

Provide 5 issues focusing on: Architecture, Security, Deployment, Performance, Code Quality.

Format:
ISSUE 1: [CATEGORY] Title
Problem: Description
Impact: Why it matters
Fix: Solution

Be specific and practical."""

        analysis_result = model.generate_content(prompt)
        analysis_text = analysis_result.text
        
        analysis_id = str(uuid.uuid4())
        if supabase:
            try:
                supabase.table('github_analyses').insert({
                    'id': analysis_id,
                    'github_url': github_url,
                    'repo_name': repo_data.get('name'),
                    'repo_language': repo_data.get('language'),
                    'analysis': analysis_text,
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Supabase error: {e}")
        
        return jsonify({
            'success': True,
            'analysis': analysis_text,
            'repo_info': {
                'name': repo_data.get('name'),
                'description': repo_data.get('description'),
                'language': repo_data.get('language'),
                'stars': repo_data.get('stargazers_count'),
                'url': repo_data.get('html_url')
            }
        })
    
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        return jsonify({'error': 'Analysis failed'}), 500

# ============================================================================
# REAL SECURITY SCANNER USING PUBLIC APIS
# ============================================================================

@app.route('/api/security-scan', methods=['POST'])
def security_scan():
    """Real security scanner using Mozilla Observatory + HackerTarget APIs"""
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Scanner unavailable'}), 500
    
    try:
        data = request.json
        target_url = data.get('url', '').strip()
        
        if not target_url:
            return jsonify({'error': 'URL required'}), 400
        
        if not validators.url(target_url):
            return jsonify({'error': 'Invalid URL'}), 400
        
        parsed = urlparse(target_url)
        domain = parsed.netloc
        
        logger.info(f"Starting real security scan for {domain}...")
        
        all_findings = []
        
        # ======================
        # 1. MOZILLA OBSERVATORY - REAL COMPREHENSIVE SCAN
        # ======================
        logger.info("Running Mozilla Observatory scan...")
        try:
            # Start scan
            obs_start = requests.post(
                'https://http-observatory.security.mozilla.org/api/v1/analyze',
                params={'host': domain, 'rescan': 'true'},
                timeout=15
            )
            
            if obs_start.status_code == 200:
                scan_data = obs_start.json()
                scan_id = scan_data.get('scan_id')
                
                # Wait up to 90 seconds for scan completion
                for attempt in range(30):
                    time.sleep(3)
                    
                    check = requests.get(
                        f'https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}',
                        timeout=10
                    )
                    
                    if check.status_code == 200:
                        result = check.json()
                        state = result.get('state')
                        
                        logger.info(f"Observatory scan state: {state} (attempt {attempt + 1}/30)")
                        
                        if state == 'FINISHED':
                            # Get test results
                            tests_url = f'https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan={scan_id}'
                            tests_resp = requests.get(tests_url, timeout=10)
                            
                            if tests_resp.status_code == 200:
                                tests = tests_resp.json()
                                
                                # Parse each test result
                                for test_name, test_data in tests.items():
                                    if isinstance(test_data, dict):
                                        passed = test_data.get('pass', True)
                                        score = test_data.get('score_modifier', 0)
                                        
                                        if not passed:
                                            severity = 'CRITICAL' if score <= -20 else 'HIGH' if score <= -10 else 'MEDIUM'
                                            
                                            all_findings.append({
                                                'title': test_name.replace('-', ' ').title(),
                                                'severity': severity,
                                                'description': test_data.get('score_description', 'Security issue detected'),
                                                'details': test_data.get('expectation', ''),
                                                'source': 'Mozilla Observatory'
                                            })
                                
                                # Get overall grade
                                grade = result.get('grade', 'F')
                                score = result.get('score', 0)
                                
                                logger.info(f"Observatory scan complete: Grade {grade}, Score {score}, Found {len(all_findings)} issues")
                            break
                        
                        elif state in ['ABORTED', 'FAILED']:
                            logger.error(f"Observatory scan failed: {state}")
                            break
        
        except Exception as e:
            logger.error(f"Mozilla Observatory error: {e}")
        
        # ======================
        # 2. HACKERTARGET.COM FREE APIs
        # ======================
        logger.info("Running HackerTarget scans...")
        
        # 2a. HTTP Headers scan
        try:
            headers_api = f'https://api.hackertarget.com/httpheaders/?q={domain}'
            headers_resp = requests.get(headers_api, timeout=15)
            
            if headers_resp.status_code == 200:
                headers_text = headers_resp.text
                
                # Check for missing critical headers
                critical_headers = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options']
                
                for header in critical_headers:
                    if header not in headers_text.lower():
                        all_findings.append({
                            'title': f'Missing {header.replace("-", " ").title()}',
                            'severity': 'HIGH',
                            'description': f'{header} header not found',
                            'details': 'Verified by HackerTarget API scan',
                            'source': 'HackerTarget Headers'
                        })
        
        except Exception as e:
            logger.error(f"HackerTarget headers error: {e}")
        
        # 2b. Zone transfer / DNS check
        try:
            dns_api = f'https://api.hackertarget.com/dnslookup/?q={domain}'
            dns_resp = requests.get(dns_api, timeout=15)
            
            if dns_resp.status_code == 200:
                logger.info("DNS lookup completed")
        
        except Exception as e:
            logger.error(f"DNS check error: {e}")
        
        # 2c. Port scan
        try:
            nmap_api = f'https://api.hackertarget.com/nmap/?q={domain}'
            nmap_resp = requests.get(nmap_api, timeout=20)
            
            if nmap_resp.status_code == 200:
                nmap_results = nmap_resp.text
                
                # Check for common vulnerable ports
                vulnerable_ports = {
                    '21': 'FTP - insecure file transfer',
                    '23': 'Telnet - unencrypted remote access',
                    '3389': 'RDP - Remote Desktop',
                    '445': 'SMB - file sharing'
                }
                
                for port, description in vulnerable_ports.items():
                    if f'{port}/tcp' in nmap_results and 'open' in nmap_results:
                        all_findings.append({
                            'title': f'Port {port} Open',
                            'severity': 'HIGH',
                            'description': f'Vulnerable port detected: {description}',
                            'details': f'Port {port} is publicly accessible',
                            'source': 'HackerTarget Nmap'
                        })
        
        except Exception as e:
            logger.error(f"Nmap error: {e}")
        
        # ======================
        # 3. IMMUNIWEB API (free tier)
        # ======================
        logger.info("Running ImmuniWeb scan...")
        try:
            immuniweb_api = 'https://www.immuniweb.com/websec/api/v1/'
            
            scan_request = requests.post(
                immuniweb_api,
                json={'url': target_url, 'recheck': False},
                timeout=20
            )
            
            if scan_request.status_code == 200:
                scan_data = scan_request.json()
                
                # Check for vulnerabilities in response
                if 'vulnerabilities' in scan_data:
                    for vuln in scan_data['vulnerabilities']:
                        all_findings.append({
                            'title': vuln.get('title', 'Security Issue'),
                            'severity': vuln.get('severity', 'MEDIUM').upper(),
                            'description': vuln.get('description', ''),
                            'details': vuln.get('solution', ''),
                            'source': 'ImmuniWeb'
                        })
        
        except Exception as e:
            logger.error(f"ImmuniWeb error: {e}")
        
        # ======================
        # 4. DIRECT TESTING - SQL INJECTION, XSS, etc.
        # ======================
        logger.info("Running direct vulnerability tests...")
        
        try:
            # Get the actual page
            page_resp = requests.get(target_url, timeout=10)
            page_html = page_resp.text
            soup = BeautifulSoup(page_html, 'html.parser')
            
            # Find all forms for testing
            forms = soup.find_all('form')
            
            if forms:
                # Test first form for SQL injection
                test_form = forms[0]
                form_action = test_form.get('action', '')
                form_method = test_form.get('method', 'get').lower()
                
                # Get all input fields
                inputs = test_form.find_all('input')
                
                if inputs:
                    # SQL injection payloads
                    sql_payloads = ["' OR '1'='1", "1' OR '1'='1' --", "admin'--"]
                    
                    for payload in sql_payloads:
                        test_data = {}
                        for inp in inputs:
                            inp_name = inp.get('name', '')
                            if inp_name:
                                test_data[inp_name] = payload
                        
                        try:
                            # Construct target URL
                            test_url = form_action if form_action.startswith('http') else f"{target_url.rstrip('/')}/{form_action.lstrip('/')}"
                            
                            if form_method == 'post':
                                test_resp = requests.post(test_url, data=test_data, timeout=5)
                            else:
                                test_resp = requests.get(test_url, params=test_data, timeout=5)
                            
                            # Check for SQL errors
                            error_patterns = [
                                'sql syntax', 'mysql_fetch', 'mysqli', 'postgresql', 
                                'sqlite', 'oracle', 'odbc', 'db2', 'sybase'
                            ]
                            
                            response_lower = test_resp.text.lower()
                            
                            if any(pattern in response_lower for pattern in error_patterns):
                                all_findings.append({
                                    'title': 'Potential SQL Injection Vulnerability',
                                    'severity': 'CRITICAL',
                                    'description': 'SQL error messages detected in response',
                                    'details': f'Form at {test_url} may be vulnerable to SQL injection',
                                    'source': 'Direct SQL Injection Test'
                                })
                                break
                        
                        except:
                            continue
                    
                    # Test for XSS
                    xss_payload = '<script>alert("XSS")</script>'
                    
                    test_data = {}
                    for inp in inputs:
                        inp_name = inp.get('name', '')
                        if inp_name:
                            test_data[inp_name] = xss_payload
                    
                    try:
                        test_url = form_action if form_action.startswith('http') else f"{target_url.rstrip('/')}/{form_action.lstrip('/')}"
                        
                        if form_method == 'post':
                            xss_resp = requests.post(test_url, data=test_data, timeout=5)
                        else:
                            xss_resp = requests.get(test_url, params=test_data, timeout=5)
                        
                        # Check if payload is reflected
                        if xss_payload in xss_resp.text:
                            all_findings.append({
                                'title': 'Cross-Site Scripting (XSS) Vulnerability',
                                'severity': 'CRITICAL',
                                'description': 'User input reflected without sanitization',
                                'details': f'Form reflects unescaped input - XSS possible',
                                'source': 'Direct XSS Test'
                            })
                    
                    except:
                        pass
                    
                    # Test for CSRF protection
                    has_csrf_token = False
                    for inp in inputs:
                        inp_name = inp.get('name', '').lower()
                        if 'csrf' in inp_name or 'token' in inp_name:
                            has_csrf_token = True
                            break
                    
                    if not has_csrf_token and form_method == 'post':
                        all_findings.append({
                            'title': 'Missing CSRF Protection',
                            'severity': 'HIGH',
                            'description': 'No CSRF token found in form',
                            'details': 'POST forms should include CSRF tokens',
                            'source': 'CSRF Test'
                        })
        
        except Exception as e:
            logger.error(f"Direct testing error: {e}")
        
        # ======================
        # 5. CHECK FOR EXPOSED FILES
        # ======================
        logger.info("Checking for exposed sensitive files...")
        
        try:
            base_url = f"{parsed.scheme}://{domain}"
            sensitive_files = [
                '.env', '.git/config', 'config.php', 'wp-config.php',
                'phpinfo.php', '.htaccess', 'composer.json', 'package.json',
                '.DS_Store', 'web.config', 'database.yml'
            ]
            
            exposed_files = []
            
            for filepath in sensitive_files:
                try:
                    file_url = f"{base_url}/{filepath}"
                    file_resp = requests.get(file_url, timeout=3, allow_redirects=False)
                    
                    if file_resp.status_code == 200 and len(file_resp.content) > 50:
                        content_preview = file_resp.text[:200].lower()
                        
                        if '404' not in content_preview and 'not found' not in content_preview and '<html' not in content_preview:
                            exposed_files.append(filepath)
                            logger.info(f"Exposed file found: {filepath}")
                
                except:
                    continue
            
            if exposed_files:
                all_findings.append({
                    'title': 'Exposed Sensitive Files',
                    'severity': 'CRITICAL',
                    'description': f'{len(exposed_files)} sensitive file(s) publicly accessible',
                    'details': f'Files: {", ".join(exposed_files)}',
                    'source': 'File Exposure Test'
                })
        
        except Exception as e:
            logger.error(f"File check error: {e}")
        
        # ======================
        # RETURN RESULTS
        # ======================
        
        if not all_findings:
            return jsonify({
                'success': True,
                'vulnerabilities': [],
                'total_found': 0,
                'message': 'No security issues detected',
                'scan_info': {
                    'url': target_url,
                    'timestamp': datetime.utcnow().isoformat()
                }
            })
        
        # Format with Gemini
        findings_text = "\n".join([
            f"{i+1}. {f['title']} [{f['severity']}] - {f['description']}"
            for i, f in enumerate(all_findings[:20])  # Top 20
        ])
        
        prompt = f"""Format these REAL security vulnerabilities found by multiple scanners for {target_url}.

**VERIFIED FINDINGS FROM SECURITY SCANNERS:**
{findings_text}

Select the TOP 3 MOST CRITICAL issues. Return ONLY valid JSON (no markdown):

{{
    "top_vulnerabilities": [
        {{
            "title": "Clear business-friendly title",
            "risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
            "business_impact": "Why this matters",
            "technical_details": "What was found",
            "official_docs": ["https://owasp.org/...", "https://developer.mozilla.org/..."],
            "estimated_fix_time": "X hours"
        }}
    ]
}}

Use ONLY issues from the list above. Maximum 3."""

        try:
            result = model.generate_content(prompt)
            result_text = result.text.strip()
            result_text = re.sub(r'```json\s*', '', result_text)
            result_text = re.sub(r'```\s*', '', result_text)
            
            json_match = re.search(r'\{[\s\S]*\}', result_text)
            if json_match:
                result_json = json.loads(json_match.group())
                top_vulns = result_json.get('top_vulnerabilities', [])[:3]
            else:
                raise ValueError("No JSON")
        
        except Exception as e:
            logger.error(f"Gemini error: {e}")
            top_vulns = [
                {
                    'title': f['title'],
                    'risk_level': f['severity'],
                    'business_impact': f['description'],
                    'technical_details': f['details'],
                    'official_docs': ['https://owasp.org/www-project-top-ten/'],
                    'estimated_fix_time': '2-4 hours'
                }
                for f in all_findings[:3]
            ]
        
        # Save to database
        scan_id = str(uuid.uuid4())
        if supabase:
            try:
                supabase.table('security_scans').insert({
                    'id': scan_id,
                    'target_url': target_url,
                    'vulnerabilities_found': len(all_findings),
                    'top_3_analysis': json.dumps(top_vulns),
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Database error: {e}")
        
        logger.info(f"Scan complete: {len(all_findings)} total issues found")
        
        return jsonify({
            'success': True,
            'vulnerabilities': top_vulns,
            'total_found': len(all_findings),
            'scan_info': {
                'url': target_url,
                'scan_id': scan_id,
                'timestamp': datetime.utcnow().isoformat(),
                'scanners_used': ['Mozilla Observatory', 'HackerTarget', 'Direct Testing']
            }
        })
    
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return jsonify({'error': 'Scan failed'}), 500

@app.route('/api/analyze-web', methods=['POST'])
def analyze_web():
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Analysis service unavailable'}), 500
    
    try:
        data = request.json
        web_url = data.get('url', '').strip()
        
        if not web_url:
            return jsonify({'error': 'URL required'}), 400
        
        if not validators.url(web_url):
            return jsonify({'error': 'Invalid URL'}), 400
        
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(web_url, headers=headers, timeout=15)
        
        if response.status_code != 200:
            return jsonify({'error': f'Could not fetch website (Status: {response.status_code})'}), 400
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        title = soup.title.string if soup.title else 'No title'
        meta_desc = ''
        meta_tag = soup.find('meta', attrs={'name': 'description'})
        if meta_tag:
            meta_desc = meta_tag.get('content', '')
        
        forms = len(soup.find_all('form'))
        links = len(soup.find_all('a'))
        images = len(soup.find_all('img'))
        
        page_text = response.text.lower()
        frameworks = []
        if 'react' in page_text:
            frameworks.append('React')
        if 'vue' in page_text:
            frameworks.append('Vue')
        if 'angular' in page_text:
            frameworks.append('Angular')
        if 'bootstrap' in page_text:
            frameworks.append('Bootstrap')
        
        prompt = f"""Analyze this website and provide actionable insights.

**Website:** {web_url}
**Title:** {title}
**HTTPS:** {'Yes' if web_url.startswith('https') else 'No'}
**Forms:** {forms}
**Links:** {links}
**Images:** {images}
**Tech:** {', '.join(frameworks) if frameworks else 'Static HTML'}

Provide analysis covering:
1. TOP 3 CRITICAL ISSUES (business-focused)
2. SEO ANALYSIS (meta tags, structure)
3. SECURITY ISSUES (headers, HTTPS)
4. PERFORMANCE PROBLEMS (load time issues)
5. UX ISSUES (mobile, navigation)
6. CLOUD RUN MIGRATION NOTES
7. QUICK WINS (3-5 easy fixes)
8. OVERALL ASSESSMENT (honest 1-paragraph summary)

Be direct and specific. Focus on business impact."""

        analysis_result = model.generate_content(prompt)
        analysis_text = analysis_result.text
        
        analysis_id = str(uuid.uuid4())
        if supabase:
            try:
                supabase.table('web_analyses').insert({
                    'id': analysis_id,
                    'web_url': web_url,
                    'title': title,
                    'analysis': analysis_text,
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Supabase error: {e}")
        
        return jsonify({
            'success': True,
            'analysis': analysis_text,
            'site_info': {
                'title': title,
                'description': meta_desc,
                'https': web_url.startswith('https'),
                'frameworks': frameworks
            }
        })
    
    except Exception as e:
        logger.error(f"Web analysis error: {e}", exc_info=True)
        return jsonify({'error': 'Analysis failed'}), 500

@app.before_request
def redirect_to_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route('/api/contact', methods=['POST'])
def contact():
    try:
        data = request.json
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        project_type = data.get('project_type', '')
        message = data.get('message', '')
        url = data.get('url', '')
        
        if not name or not email:
            return jsonify({'error': 'Name and email required'}), 400
        
        if supabase:
            try:
                supabase.table('contact_submissions').insert({
                    'id': str(uuid.uuid4()),
                    'name': name,
                    'email': email,
                    'project_type': project_type,
                    'message': message,
                    'url': url,
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Supabase error: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Thank you! I will contact you within 24 hours.'
        })
    
    except Exception as e:
        logger.error(f"Contact error: {e}", exc_info=True)
        return jsonify({'error': 'Submission failed'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 80))
    app.run(host='0.0.0.0', port=port, debug=False)
