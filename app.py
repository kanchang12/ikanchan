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

import subprocess
import json
import os

@app.route('/api/security-scan', methods=['POST'])
def security_scan():
    """Real security scanner using actual open-source tools"""
    
    try:
        data = request.json
        target_url = data.get('url', '').strip()
        
        if not target_url or not validators.url(target_url):
            return jsonify({'error': 'Invalid URL'}), 400
        
        parsed = urlparse(target_url)
        domain = parsed.netloc
        
        logger.info(f"Scanning {domain} with open-source tools...")
        
        all_findings = []
        
        # ======================
        # 1. NIKTO WEB SCANNER
        # ======================
        logger.info("Running Nikto scan...")
        try:
            nikto_result = subprocess.run(
                ['nikto', '-h', target_url, '-Format', 'json', '-output', '/tmp/nikto_output.json'],
                timeout=300,
                capture_output=True,
                text=True
            )
            
            if os.path.exists('/tmp/nikto_output.json'):
                with open('/tmp/nikto_output.json', 'r') as f:
                    nikto_data = json.load(f)
                    
                    for vuln in nikto_data.get('vulnerabilities', []):
                        all_findings.append({
                            'title': vuln.get('msg', 'Security Issue'),
                            'risk_level': 'HIGH',
                            'business_impact': vuln.get('description', ''),
                            'technical_details': f"Nikto detected: {vuln.get('uri', '')}",
                            'official_docs': ['https://cirt.net/Nikto2'],
                            'estimated_fix_time': '2-4 hours'
                        })
                
                os.remove('/tmp/nikto_output.json')
        
        except Exception as e:
            logger.error(f"Nikto error: {e}")
        
        # ======================
        # 2. NMAP PORT SCAN
        # ======================
        logger.info("Running Nmap scan...")
        try:
            nmap_result = subprocess.run(
                ['nmap', '-sV', '--script=vuln', '-oX', '/tmp/nmap_output.xml', domain],
                timeout=300,
                capture_output=True,
                text=True
            )
            
            if os.path.exists('/tmp/nmap_output.xml'):
                # Parse XML output
                import xml.etree.ElementTree as ET
                tree = ET.parse('/tmp/nmap_output.xml')
                root = tree.getroot()
                
                for port in root.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        portid = port.get('portid')
                        service = port.find('service')
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        
                        # Check for vulnerable services
                        if portid in ['21', '23', '3389', '445']:
                            all_findings.append({
                                'title': f'Vulnerable Port {portid} Open',
                                'risk_level': 'HIGH',
                                'business_impact': f'{service_name} service exposed on port {portid}',
                                'technical_details': f'Nmap detected open port: {portid}/{service_name}',
                                'official_docs': ['https://nmap.org/'],
                                'estimated_fix_time': '2-4 hours'
                            })
                
                # Check for script results (vulnerabilities)
                for script in root.findall('.//script'):
                    script_id = script.get('id', '')
                    if 'vuln' in script_id or 'cve' in script_id.lower():
                        all_findings.append({
                            'title': script_id.replace('-', ' ').title(),
                            'risk_level': 'HIGH',
                            'business_impact': 'Vulnerability detected by Nmap',
                            'technical_details': script.get('output', '')[:200],
                            'official_docs': ['https://nmap.org/'],
                            'estimated_fix_time': '4-8 hours'
                        })
                
                os.remove('/tmp/nmap_output.xml')
        
        except Exception as e:
            logger.error(f"Nmap error: {e}")
        
        # ======================
        # 3. WAPITI WEB VULNERABILITY SCANNER
        # ======================
        logger.info("Running Wapiti scan...")
        try:
            wapiti_result = subprocess.run(
                ['wapiti', '-u', target_url, '-f', 'json', '-o', '/tmp/wapiti_output.json', '--flush-session'],
                timeout=600,
                capture_output=True,
                text=True
            )
            
            if os.path.exists('/tmp/wapiti_output.json'):
                with open('/tmp/wapiti_output.json', 'r') as f:
                    wapiti_data = json.load(f)
                    
                    for vuln_type, vulns in wapiti_data.get('vulnerabilities', {}).items():
                        for vuln in vulns:
                            severity = vuln.get('level', 1)
                            risk = 'CRITICAL' if severity >= 3 else 'HIGH' if severity >= 2 else 'MEDIUM'
                            
                            all_findings.append({
                                'title': vuln_type.replace('_', ' ').title(),
                                'risk_level': risk,
                                'business_impact': vuln.get('info', ''),
                                'technical_details': f"Found at: {vuln.get('path', '')}",
                                'official_docs': ['https://wapiti-scanner.github.io/'],
                                'estimated_fix_time': '4-8 hours'
                            })
                
                os.remove('/tmp/wapiti_output.json')
        
        except Exception as e:
            logger.error(f"Wapiti error: {e}")
        
        # ======================
        # 4. SQLMAP FOR SQL INJECTION
        # ======================
        logger.info("Running SQLMap scan...")
        try:
            sqlmap_result = subprocess.run(
                ['sqlmap', '-u', target_url, '--batch', '--crawl=2', '--level=1', '--risk=1', '--output-dir=/tmp/sqlmap'],
                timeout=300,
                capture_output=True,
                text=True
            )
            
            # Check if SQLMap found vulnerabilities
            if 'sqlmap identified the following injection point' in sqlmap_result.stdout:
                all_findings.append({
                    'title': 'SQL Injection Vulnerability',
                    'risk_level': 'CRITICAL',
                    'business_impact': 'Database can be compromised - data theft possible',
                    'technical_details': 'SQLMap detected SQL injection vulnerability',
                    'official_docs': ['https://owasp.org/www-community/attacks/SQL_Injection'],
                    'estimated_fix_time': '8-16 hours'
                })
        
        except Exception as e:
            logger.error(f"SQLMap error: {e}")
        
        # ======================
        # 5. TESTSSL.SH FOR SSL/TLS
        # ======================
        if target_url.startswith('https://'):
            logger.info("Running testssl.sh...")
            try:
                testssl_result = subprocess.run(
                    ['testssl.sh', '--jsonfile', '/tmp/testssl_output.json', domain],
                    timeout=300,
                    capture_output=True,
                    text=True
                )
                
                if os.path.exists('/tmp/testssl_output.json'):
                    with open('/tmp/testssl_output.json', 'r') as f:
                        for line in f:
                            try:
                                ssl_data = json.loads(line)
                                severity = ssl_data.get('severity', '')
                                
                                if severity in ['HIGH', 'CRITICAL', 'MEDIUM']:
                                    all_findings.append({
                                        'title': ssl_data.get('id', 'SSL/TLS Issue'),
                                        'risk_level': severity,
                                        'business_impact': ssl_data.get('finding', ''),
                                        'technical_details': 'Detected by testssl.sh',
                                        'official_docs': ['https://testssl.sh/'],
                                        'estimated_fix_time': '2-4 hours'
                                    })
                            except:
                                continue
                    
                    os.remove('/tmp/testssl_output.json')
            
            except Exception as e:
                logger.error(f"testssl.sh error: {e}")
        
        # ======================
        # 6. NUCLEI VULNERABILITY SCANNER
        # ======================
        logger.info("Running Nuclei scan...")
        try:
            nuclei_result = subprocess.run(
                ['nuclei', '-u', target_url, '-json', '-o', '/tmp/nuclei_output.json'],
                timeout=300,
                capture_output=True,
                text=True
            )
            
            if os.path.exists('/tmp/nuclei_output.json'):
                with open('/tmp/nuclei_output.json', 'r') as f:
                    for line in f:
                        try:
                            nuclei_data = json.loads(line)
                            
                            severity = nuclei_data.get('info', {}).get('severity', 'medium').upper()
                            
                            all_findings.append({
                                'title': nuclei_data.get('info', {}).get('name', 'Security Issue'),
                                'risk_level': severity,
                                'business_impact': nuclei_data.get('info', {}).get('description', ''),
                                'technical_details': f"Template: {nuclei_data.get('template-id', '')}",
                                'official_docs': ['https://nuclei.projectdiscovery.io/'],
                                'estimated_fix_time': '2-4 hours'
                            })
                        except:
                            continue
                
                os.remove('/tmp/nuclei_output.json')
        
        except Exception as e:
            logger.error(f"Nuclei error: {e}")
        
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
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        all_findings.sort(key=lambda x: severity_order.get(x['risk_level'], 4))
        
        top_3 = all_findings[:3]
        
        # Save to DB
        scan_id = str(uuid.uuid4())
        if supabase:
            try:
                supabase.table('security_scans').insert({
                    'id': scan_id,
                    'target_url': target_url,
                    'vulnerabilities_found': len(all_findings),
                    'top_3_analysis': json.dumps(top_3),
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"DB error: {e}")
        
        logger.info(f"Scan complete: {len(all_findings)} issues found")
        
        return jsonify({
            'success': True,
            'vulnerabilities': top_3,
            'total_found': len(all_findings),
            'scan_info': {
                'url': target_url,
                'scan_id': scan_id,
                'timestamp': datetime.utcnow().isoformat(),
                'tools_used': ['Nikto', 'Nmap', 'Wapiti', 'SQLMap', 'testssl.sh', 'Nuclei']
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
