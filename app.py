import os
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect
import google.generativeai as genai
import requests
from supabase import create_client, Client
from dotenv import load_dotenv
import validators
from bs4 import BeautifulSoup
import re
import json

load_dotenv()

app = Flask(__name__)

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

# Sales chatbot system prompt
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

**Portfolio (mention when relevant):**
- CareCircle (Healthcare) - NHS-ready medication adherence platform with zero-data architecture
- HomeRule (Real Estate) - UK planning permission checker
- TrueSkills (Education) - Anti-cheating assessment platform
- MathTales (EdTech) - Fairy tale-based math learning for kids
- FindingUrWay (Travel) - AI travel planner
- WizardsTrial (Puzzle/Gaming)

**Key Differentiators:**
- Solo founder who ships fast
- Real healthcare, education, travel, real estate experience
- Cloud Run and serverless expert
- End-to-end encryption and privacy-first approach
- Leeds-based, UK-focused

**Your Goal:**
- Understand the customer's problem
- Qualify if it's an idea needing building OR broken project needing fixing
- Highlight relevant portfolio work
- Book free 30-min consultation
- Be professional, concise, and helpful
- For Leeds-based clients, mention local presence

**Tone:** Professional, confident, solution-focused. No emojis."""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    """Gemini-powered sales chatbot"""
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Chat service unavailable'}), 500
    
    try:
        data = request.json
        user_message = data.get('message', '')
        conversation_history = data.get('history', [])
        session_id = data.get('session_id', str(uuid.uuid4()))
        
        if not user_message:
            return jsonify({'error': 'Message required'}), 400
        
        # Build conversation context
        chat_history = [SALES_CHATBOT_PROMPT]
        for msg in conversation_history[-10:]:  # Last 10 messages for context
            role = msg.get('role', 'user')
            content = msg.get('content', '')
            chat_history.append(f"{role}: {content}")
        
        chat_history.append(f"user: {user_message}")
        
        # Generate response
        prompt = "\n".join(chat_history) + "\nassistant:"
        response = model.generate_content(prompt)
        bot_response = response.text
        
        # Store in Supabase
        if supabase:
            try:
                supabase.table('chat_logs').insert({
                    'session_id': session_id,
                    'user_message': user_message,
                    'bot_response': bot_response,
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                print(f"Supabase error: {e}")
        
        return jsonify({
            'response': bot_response,
            'session_id': session_id
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-github', methods=['POST'])
def analyze_github():
    """Analyze GitHub repository"""
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Analysis service unavailable'}), 500
    
    try:
        data = request.json
        github_url = data.get('url', '').strip()
        
        if not github_url:
            return jsonify({'error': 'GitHub URL required'}), 400
        
        # Extract owner and repo
        parts = github_url.replace('https://github.com/', '').replace('http://github.com/', '').split('/')
        if len(parts) < 2:
            return jsonify({'error': 'Invalid GitHub URL format'}), 400
        
        owner, repo = parts[0], parts[1]
        
        # Get repo info from GitHub API
        api_url = f'https://api.github.com/repos/{owner}/{repo}'
        response = requests.get(api_url, timeout=10)
        
        if response.status_code != 200:
            return jsonify({'error': 'Could not fetch repository. Please check the URL'}), 400
        
        repo_data = response.json()
        
        # Get file list
        contents_url = f'https://api.github.com/repos/{owner}/{repo}/contents'
        contents = requests.get(contents_url, timeout=10)
        files = []
        if contents.status_code == 200:
            file_data = contents.json()
            if isinstance(file_data, list):
                files = [f['name'] for f in file_data if isinstance(f, dict) and f.get('type') == 'file']
        
        # Get README if exists
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
        
        # Analyze with Gemini
        prompt = f"""Analyze this GitHub repository and provide exactly 5 critical issues for improvement.

**Repository Information:**
- Name: {repo_data.get('name')}
- Description: {repo_data.get('description', 'No description provided')}
- Primary Language: {repo_data.get('language', 'Not specified')}
- Stars: {repo_data.get('stargazers_count', 0)}
- Forks: {repo_data.get('forks_count', 0)}
- Open Issues: {repo_data.get('open_issues_count', 0)}
- Files in root: {', '.join(files[:30])}

**README Preview:**
{readme_content if readme_content else 'No README found'}

**Analysis Focus Areas:**
1. Architecture and Code Structure
2. Security Vulnerabilities
3. Deployment and DevOps
4. Performance Optimization
5. Code Quality and Testing

**Output Format (EXACTLY 5 issues):**

ISSUE 1: [CATEGORY] Title
Problem: Clear description of the problem
Impact: Why this matters
Fix: Specific, actionable solution

ISSUE 2: [CATEGORY] Title
Problem: Clear description
Impact: Why this matters
Fix: Specific solution

[Continue for all 5 issues]

**Cloud Run Deployment Notes:**
[Brief suggestions for deploying this to Google Cloud Run]

Be specific, practical, and prioritize issues by severity."""

        analysis_result = model.generate_content(prompt)
        analysis_text = analysis_result.text
        
        # Store in Supabase
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
                print(f"Supabase error: {e}")
        
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
    
    except requests.Timeout:
        return jsonify({'error': 'Request timeout. Please try again'}), 500
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

# ============================================================================
# ADD THIS ROUTE TO YOUR EXISTING app.py
# Insert this AFTER the @app.route('/api/analyze-github') route (after line 248)
# and BEFORE the @app.route('/api/analyze-web') route (before line 250)
# ============================================================================

import time
from urllib.parse import urlparse

@app.route('/api/security-scan', methods=['POST'])
def security_scan():
    """Real security scanner using Mozilla Observatory and SSL Labs APIs"""
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Security scanner unavailable'}), 500
    
    try:
        data = request.json
        target_url = data.get('url', '').strip()
        
        if not target_url:
            return jsonify({'error': 'URL required'}), 400
        
        if not validators.url(target_url):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Extract domain
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path
        
        all_findings = []
        
        # ======================
        # 1. MOZILLA OBSERVATORY SCAN (FREE)
        # ======================
        try:
            # Start scan
            obs_start = requests.post(
                'https://http-observatory.security.mozilla.org/api/v1/analyze',
                params={
                    'host': domain,
                    'rescan': 'true',
                    'hidden': 'true'
                },
                timeout=10
            )
            
            if obs_start.status_code == 200:
                # Wait for scan to complete
                time.sleep(3)
                
                # Get results
                obs_result = requests.get(
                    f'https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}',
                    timeout=10
                )
                
                if obs_result.status_code == 200:
                    obs_data = obs_result.json()
                    
                    # Get detailed test results
                    obs_tests = requests.get(
                        f'https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan={obs_data.get("scan_id")}',
                        timeout=10
                    )
                    
                    if obs_tests.status_code == 200:
                        tests_data = obs_tests.json()
                        
                        # Parse failed tests
                        for test_name, test_result in tests_data.items():
                            if isinstance(test_result, dict):
                                score = test_result.get('score_modifier', 0)
                                if score < 0:  # Failed test
                                    severity = 'CRITICAL' if score <= -20 else 'HIGH' if score <= -10 else 'MEDIUM'
                                    all_findings.append({
                                        'test': test_name,
                                        'severity': severity,
                                        'description': test_result.get('score_description', ''),
                                        'details': test_result.get('pass', False),
                                        'source': 'Mozilla Observatory'
                                    })
        except Exception as e:
            print(f"Mozilla Observatory error: {e}")
        
        # ======================
        # 2. SSL LABS SCAN (FREE)
        # ======================
        if target_url.startswith('https://'):
            try:
                # Start SSL scan
                ssl_start = requests.get(
                    'https://api.ssllabs.com/api/v3/analyze',
                    params={
                        'host': domain,
                        'startNew': 'on',
                        'all': 'done'
                    },
                    timeout=10
                )
                
                if ssl_start.status_code == 200:
                    ssl_data = ssl_start.json()
                    
                    # Check if scan is ready (it can take time)
                    status = ssl_data.get('status')
                    
                    if status == 'READY' or status == 'READY':
                        endpoints = ssl_data.get('endpoints', [])
                        for endpoint in endpoints:
                            grade = endpoint.get('grade', 'T')
                            
                            # Check grade
                            if grade in ['C', 'D', 'E', 'F', 'T', 'M']:
                                severity = 'CRITICAL' if grade in ['F', 'T', 'M'] else 'HIGH'
                                all_findings.append({
                                    'test': 'SSL/TLS Configuration',
                                    'severity': severity,
                                    'description': f'SSL Labs Grade: {grade}',
                                    'details': endpoint.get('statusMessage', ''),
                                    'source': 'SSL Labs'
                                })
                            
                            # Check for specific issues
                            details = endpoint.get('details', {})
                            
                            # Check protocols
                            protocols = details.get('protocols', [])
                            for protocol in protocols:
                                if protocol.get('name') in ['TLS', 'SSL'] and protocol.get('version') in ['1.0', '1.1', '2.0', '3.0']:
                                    all_findings.append({
                                        'test': 'Outdated TLS/SSL Protocol',
                                        'severity': 'HIGH',
                                        'description': f'Using {protocol.get("name")} {protocol.get("version")}',
                                        'details': 'Upgrade to TLS 1.2 or 1.3',
                                        'source': 'SSL Labs'
                                    })
            except Exception as e:
                print(f"SSL Labs error: {e}")
        
        # ======================
        # 3. BASIC SECURITY CHECKS
        # ======================
        try:
            headers_check = requests.get(target_url, timeout=10, allow_redirects=True)
            
            # Check security headers
            required_headers = {
                'Strict-Transport-Security': 'HSTS header missing',
                'Content-Security-Policy': 'CSP header missing',
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing'
            }
            
            for header, description in required_headers.items():
                if header not in headers_check.headers:
                    all_findings.append({
                        'test': header,
                        'severity': 'HIGH' if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else 'MEDIUM',
                        'description': description,
                        'details': f'Add {header} header to your server configuration',
                        'source': 'Header Check'
                    })
            
            # Check if HTTPS
            if not target_url.startswith('https://'):
                all_findings.append({
                    'test': 'HTTPS',
                    'severity': 'CRITICAL',
                    'description': 'Website not using HTTPS',
                    'details': 'All websites should use HTTPS encryption',
                    'source': 'Basic Check'
                })
        except Exception as e:
            print(f"Basic checks error: {e}")
        
        # ======================
        # 4. CHECK FOR EXPOSED FILES
        # ======================
        sensitive_files = [
            '.git/config',
            '.env',
            'config.php',
            'wp-config.php.bak',
            '.DS_Store',
            'phpinfo.php'
        ]
        
        base_url = target_url.rstrip('/')
        exposed = []
        
        for file_path in sensitive_files:
            try:
                test_url = f"{base_url}/{file_path}"
                response = requests.get(test_url, timeout=3, allow_redirects=False)
                if response.status_code == 200 and len(response.content) > 10:
                    exposed.append(file_path)
            except:
                continue
        
        if exposed:
            all_findings.append({
                'test': 'Exposed Sensitive Files',
                'severity': 'CRITICAL',
                'description': f'Found {len(exposed)} exposed files',
                'details': f'Files accessible: {", ".join(exposed)}',
                'source': 'File Check'
            })
        
        # If no issues found
        if not all_findings:
            return jsonify({
                'success': True,
                'vulnerabilities': [],
                'message': 'Great news! No major security issues detected.',
                'scan_info': {
                    'url': target_url,
                    'timestamp': datetime.utcnow().isoformat()
                }
            })
        
        # ======================
        # USE GEMINI TO ANALYZE AND PRIORITIZE TOP 3
        # ======================
        findings_text = "\n\n".join([
            f"**{f['test']}** (Severity: {f['severity']}) [Source: {f['source']}]\n"
            f"Description: {f['description']}\n"
            f"Details: {f['details']}"
            for f in all_findings
        ])
        
        gemini_prompt = f"""You are a cybersecurity expert analyzing REAL vulnerability scan results from Mozilla Observatory, SSL Labs, and security tools.

**Website Scanned:** {target_url}

**Real Findings from Security Scanners:**
{findings_text}

**Your Task:**
Select the TOP 3 MOST CRITICAL issues from these REAL scan results and explain them in business terms.

For each of the TOP 3, provide:
1. **Title**: Business-friendly name
2. **Risk Level**: CRITICAL, HIGH, or MEDIUM (keep original severity)
3. **Business Impact**: Real-world consequences
4. **Technical Details**: What the scan found
5. **Official Docs**: 2-3 REAL official documentation URLs (OWASP, MDN, Mozilla, W3C only)
6. **Estimated Fix Time**: Realistic estimate

**IMPORTANT:**
- These are REAL findings from actual security scans, not assumptions
- Prioritize by business risk
- Provide REAL working documentation URLs only

**Output Format (valid JSON only):**
{{
    "top_vulnerabilities": [
        {{
            "title": "Missing HTTPS Encryption",
            "risk_level": "CRITICAL",
            "business_impact": "All user data transmitted in plain text, easily intercepted",
            "technical_details": "Website using HTTP protocol without SSL/TLS encryption",
            "official_docs": [
                "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
                "https://owasp.org/www-community/controls/SecureFlag"
            ],
            "estimated_fix_time": "1-2 hours"
        }}
    ]
}}

Return ONLY valid JSON, no markdown.
"""

        gemini_response = model.generate_content(gemini_prompt)
        analysis_text = gemini_response.text
        
        # Parse JSON
        analysis_text = re.sub(r'```json\s*', '', analysis_text)
        analysis_text = re.sub(r'```\s*', '', analysis_text)
        analysis_text = analysis_text.strip()
        
        json_match = re.search(r'\{[\s\S]*\}', analysis_text)
        if json_match:
            analysis_json = json.loads(json_match.group())
        else:
            analysis_json = {
                "top_vulnerabilities": [
                    {
                        "title": f['test'],
                        "risk_level": f['severity'],
                        "business_impact": f['description'],
                        "technical_details": f['details'],
                        "official_docs": [
                            "https://developer.mozilla.org/en-US/docs/Web/Security"
                        ],
                        "estimated_fix_time": "Varies"
                    }
                    for f in all_findings[:3]
                ]
            }
        
        top_3_vulnerabilities = analysis_json.get('top_vulnerabilities', [])[:3]
        
        # Store in Supabase
        scan_id = str(uuid.uuid4())
        if supabase:
            try:
                supabase.table('security_scans').insert({
                    'id': scan_id,
                    'target_url': target_url,
                    'vulnerabilities_found': len(all_findings),
                    'top_3_analysis': json.dumps(top_3_vulnerabilities),
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                print(f"Supabase error: {e}")
        
        return jsonify({
            'success': True,
            'vulnerabilities': top_3_vulnerabilities,
            'total_found': len(all_findings),
            'scan_info': {
                'url': target_url,
                'scan_id': scan_id,
                'timestamp': datetime.utcnow().isoformat(),
                'sources': ['Mozilla Observatory', 'SSL Labs', 'Header Check', 'File Check']
            }
        })
    
    except requests.Timeout:
        return jsonify({'error': 'Request timeout'}), 500
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Failed to parse results: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/api/analyze-web', methods=['POST'])
def analyze_web():
    """Analyze live website"""
    if not GEMINI_API_KEY:
        return jsonify({'error': 'Analysis service unavailable'}), 500
    
    try:
        data = request.json
        web_url = data.get('url', '').strip()
        
        if not web_url:
            return jsonify({'error': 'Website URL required'}), 400
        
        # Validate URL
        if not validators.url(web_url):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Fetch website content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(web_url, headers=headers, timeout=15)
        
        if response.status_code != 200:
            return jsonify({'error': f'Could not fetch website. Status: {response.status_code}'}), 400
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract information
        title = soup.title.string if soup.title else 'No title'
        meta_desc = ''
        meta_tag = soup.find('meta', attrs={'name': 'description'})
        if meta_tag:
            meta_desc = meta_tag.get('content', '')
        
        # Get scripts and forms
        scripts = [s.get('src') for s in soup.find_all('script', src=True)][:10]
        forms = len(soup.find_all('form'))
        links = len(soup.find_all('a'))
        images = len(soup.find_all('img'))
        
        # Check for common frameworks
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
        
        # Analyze with Gemini
        prompt = f"""You are analyzing a website for business and technical insights. Give direct, actionable insights - NO CODE.

**Website:** {web_url}
**Title:** {title}
**HTTPS:** {'Yes' if web_url.startswith('https') else 'No'}
**Forms Found:** {forms}
**Links:** {links}
**Images:** {images}
**Tech Stack:** {', '.join(frameworks) if frameworks else 'Static HTML/Vanilla JS'}

---

## TOP 3 CRITICAL ISSUES

Identify the 3 most important problems affecting this website. Focus on business impact.

Format:
1. **[Issue Name]**
   - What's wrong
   - Why it matters
   - How to fix it (description, not code)

Example:
1. **No Security Headers**
   - Website missing basic security protections
   - Risk: Vulnerable to attacks, data theft
   - Fix: Configure server security headers (HSTS, CSP, X-Frame-Options)

Focus on: Security, SEO, Performance, User Experience

---

## SEO ANALYSIS

Check for:
- Meta description quality
- Title tag optimization
- Missing alt tags on images
- Mobile responsiveness
- Page speed issues
- Structured data (Schema.org)
- SSL certificate
- Duplicate content

Be specific about what's missing and why it matters for rankings.

---

## SECURITY ISSUES

Identify security vulnerabilities:
- HTTPS status
- Security headers (check if HSTS, CSP, X-Frame-Options are present)
- Exposed sensitive data
- Insecure forms
- Old frameworks with known vulnerabilities
- Cookie security

Explain the business risk, not just technical details.

---

## PERFORMANCE PROBLEMS

Analyze speed and performance:
- Large unoptimized images (list sizes if visible)
- Too many HTTP requests
- No caching
- Blocking resources
- Slow server response

Give actual numbers and business impact (e.g., "2.5s load time, should be under 1s - losing 20% of visitors")

---

## USER EXPERIENCE ISSUES

Check for:
- Mobile responsiveness
- Broken links
- Confusing navigation
- Poor accessibility
- Missing contact information
- Unclear calls-to-action

Focus on what hurts conversions and user satisfaction.

---

## CLOUD RUN MIGRATION

Provide insights on moving to Cloud Run:
- Current hosting type (if detectable)
- Complexity of migration
- Expected monthly cost (realistic estimate for 10k requests/month)
- Main challenges
- Expected performance improvement

---

## QUICK WINS (Do These First)

List 3-5 actionable improvements by priority:
1. [Highest impact, easiest to fix]
2. [Second priority]
3. [Third priority]

For each: What to do, expected impact, rough time/cost to fix.

---

## OVERALL ASSESSMENT

Give a honest 1-paragraph summary:
- Current state (poor/average/good)
- Biggest problems
- Recommended next steps

**BE DIRECT AND HONEST.** If the site is poorly built, say so. If it's good, say so. Focus on business impact, not technical jargon."""

        analysis_result = model.generate_content(prompt)
        analysis_text = analysis_result.text
        
        # Store in Supabase
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
                print(f"Supabase error: {e}")
        
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
    
    except requests.Timeout:
        return jsonify({'error': 'Request timeout. Website took too long to respond'}), 500
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.before_request
def redirect_to_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route('/api/contact', methods=['POST'])
def contact():
    """Handle contact form submission"""
    try:
        data = request.json
        name = data.get('name', '')
        email = data.get('email', '')
        project_type = data.get('project_type', '')
        message = data.get('message', '')
        url = data.get('url', '')
        
        if not name or not email:
            return jsonify({'error': 'Name and email required'}), 400
        
        # Store in Supabase
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
                print(f"Supabase error: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Thank you! I will contact you within 24 hours.'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 80))
    app.run(host='0.0.0.0', port=port, debug=False)
