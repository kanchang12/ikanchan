#!/usr/bin/env python3
"""
Simple blog system: add chapters, track reads
No payments. Just content + analytics.
"""

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from datetime import datetime
import json
import os
import markdown
from pathlib import Path
from functools import wraps
import secrets
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Determine if running in production
IS_PRODUCTION = os.environ.get('ENVIRONMENT', 'development') == 'production'

# Setup directories
CHAPTERS_DIR = Path('chapters')
DATA_DIR = Path('data')
CHAPTERS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# Read tracking file
READS_FILE = DATA_DIR / 'reads.json'

# Admin credentials - read from environment variables
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme123')

def load_reads():
    """Load read count data"""
    if READS_FILE.exists():
        with open(READS_FILE) as f:
            return json.load(f)
    return {}

def save_reads(reads):
    """Save read count data"""
    with open(READS_FILE, 'w') as f:
        json.dump(reads, f)

def get_all_chapters():
    """Get all chapters sorted by date (newest first)"""
    chapters = []
    for md_file in sorted(CHAPTERS_DIR.glob('*.md'), reverse=True):
        with open(md_file) as f:
            content = f.read()
        
        # Parse metadata from top of file
        lines = content.split('\n')
        metadata = {}
        body = content
        
        if lines[0].startswith('---'):
            end = 1
            while end < len(lines) and not lines[end].startswith('---'):
                line = lines[end]
                if ':' in line:
                    key, val = line.split(':', 1)
                    metadata[key.strip()] = val.strip()
                end += 1
            body = '\n'.join(lines[end+1:])
        
        reads = load_reads()
        read_count = reads.get(md_file.stem, 0)
        
        chapters.append({
            'slug': md_file.stem,
            'title': metadata.get('title', md_file.stem),
            'date': metadata.get('date', ''),
            'excerpt': metadata.get('excerpt', ''),
            'body': markdown.markdown(body),
            'reads': read_count
        })
    
    return chapters

def get_chapter_metadata_only():
    """Get chapters without full body content (for API)"""
    chapters = []
    for md_file in sorted(CHAPTERS_DIR.glob('*.md'), reverse=True):
        with open(md_file) as f:
            content = f.read()
        
        lines = content.split('\n')
        metadata = {}
        
        if lines[0].startswith('---'):
            end = 1
            while end < len(lines) and not lines[end].startswith('---'):
                line = lines[end]
                if ':' in line:
                    key, val = line.split(':', 1)
                    metadata[key.strip()] = val.strip()
                end += 1
        
        reads = load_reads()
        read_count = reads.get(md_file.stem, 0)
        
        chapters.append({
            'slug': md_file.stem,
            'title': metadata.get('title', md_file.stem),
            'date': metadata.get('date', ''),
            'excerpt': metadata.get('excerpt', ''),
            'reads': read_count
        })
    
    return chapters

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

# Routes
@app.route('/blog')
def blog_home():
    """Main blog page - list all chapters"""
    chapters = get_all_chapters()
    return render_template('blog_home.html', chapters=chapters)

@app.route('/chapter/<slug>')
def read_chapter(slug):
    """Read single chapter"""
    chapters = get_all_chapters()
    chapter = next((c for c in chapters if c['slug'] == slug), None)
    
    if not chapter:
        return "Chapter not found", 404
    
    # Track read
    reads = load_reads()
    reads[slug] = reads.get(slug, 0) + 1
    save_reads(reads)
    
    return render_template('chapter.html', chapter=chapter)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.pop('logged_in', None)
    return redirect(url_for('blog_home'))

@app.route('/admin')
@login_required
def admin_panel():
    """Admin: add new chapter"""
    chapters = get_chapter_metadata_only()
    return render_template('admin.html', chapters=chapters)

@app.route('/admin/delete/<slug>', methods=["POST", "GET"])
@login_required
def delete_chapter(slug):
    """Delete a chapter"""
    for md_file in CHAPTERS_DIR.glob('*.md'):
        if md_file.stem == slug:
            md_file.unlink()
            reads = load_reads()
            if slug in reads:
                del reads[slug]
                save_reads(reads)
            return jsonify({'status': 'ok', 'message': 'Chapter deleted'})
    
    return jsonify({'status': 'error', 'message': 'Chapter not found'}), 404

@app.route('/api/chapters')
def api_chapters():
    """JSON list of all chapters + read counts"""
    chapters = get_chapter_metadata_only()
    return jsonify([{
        'slug': c['slug'],
        'title': c['title'],
        'date': c['date'],
        'excerpt': c['excerpt'],
        'reads': c['reads']
    } for c in chapters])

@app.route('/api/upload-chapter', methods=["POST", "GET"])
@login_required
def upload_chapter():
    """Save new chapter"""
    data = request.json
    title = data.get('title', 'Untitled')
    excerpt = data.get('excerpt', '')
    content = data.get('content', '')
    
    # Create slug from title
    slug = title.lower().replace(' ', '-').replace(':', '').replace(',', '')
    slug = ''.join(c for c in slug if c.isalnum() or c == '-')
    
    # Filename with date
    date_str = datetime.now().strftime('%Y-%m-%d')
    filename = f"{date_str}_{slug}.md"
    
    # Write file with metadata
    metadata = f"""---
title: {title}
date: {date_str}
excerpt: {excerpt}
---

{content}
"""
    
    filepath = CHAPTERS_DIR / filename
    with open(filepath, 'w') as f:
        f.write(metadata)
    
    return jsonify({
        'status': 'ok',
        'slug': slug,
        'filename': filename,
        'url': f'/chapter/{slug}'
    })

@app.route('/api/analytics')
def analytics():
    """Read count by chapter"""
    chapters = get_chapter_metadata_only()
    reads = load_reads()
    
    return jsonify({
        'total_reads': sum(reads.values()),
        'chapters': sorted([{
            'title': c['title'],
            'slug': c['slug'],
            'date': c['date'],
            'reads': c['reads']
        } for c in chapters], key=lambda x: x['reads'], reverse=True)
    })

# Health check for monitoring
@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'environment': os.environ.get('ENVIRONMENT', 'development')})

if __name__ == '__main__':
    if IS_PRODUCTION:
        logger.info("Running in production mode with Gunicorn")
        # Don't run the dev server in production
        pass
    else:
        logger.info("Running in development mode with Flask dev server")
        app.run(debug=True, host='0.0.0.0', port=5000)
