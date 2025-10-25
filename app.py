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
