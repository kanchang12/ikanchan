@app.route('/api/security-scan', methods=['POST'])
def security_scan():
    """Security scanner using Mozilla Observatory API + Nikto (FREE)"""
    
    try:
        data = request.json
        target_url = data.get('url', '').strip()
        
        if not target_url or not validators.url(target_url):
            return jsonify({'error': 'Invalid URL'}), 400
        
        parsed = urlparse(target_url)
        domain = parsed.netloc
        
        logger.info(f"Scanning {domain}...")
        
        all_findings = []
        
        # ======================
        # 1. MOZILLA OBSERVATORY (60-90 seconds)
        # ======================
        logger.info("Running Mozilla Observatory...")
        try:
            obs_start = requests.post(
                'https://http-observatory.security.mozilla.org/api/v1/analyze',
                params={'host': domain, 'rescan': 'true'},
                timeout=15
            )
            
            if obs_start.status_code == 200:
                scan_id = obs_start.json().get('scan_id')
                
                for attempt in range(30):
                    time.sleep(3)
                    
                    check = requests.get(
                        f'https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}',
                        timeout=10
                    )
                    
                    if check.status_code == 200:
                        result = check.json()
                        state = result.get('state')
                        
                        logger.info(f"Observatory: {state}")
                        
                        if state == 'FINISHED':
                            tests = requests.get(
                                f'https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan={scan_id}',
                                timeout=10
                            ).json()
                            
                            for test_name, test_data in tests.items():
                                if isinstance(test_data, dict) and test_data.get('pass') == False:
                                    all_findings.append({
                                        'title': test_name.replace('-', ' ').title(),
                                        'risk_level': 'HIGH',
                                        'business_impact': test_data.get('score_description', ''),
                                        'technical_details': test_data.get('expectation', ''),
                                        'official_docs': ['https://observatory.mozilla.org/'],
                                        'estimated_fix_time': '2-4 hours'
                                    })
                            break
                        
                        elif state in ['ABORTED', 'FAILED']:
                            break
        
        except Exception as e:
            logger.error(f"Observatory error: {e}")
        
        # ======================
        # 2. NIKTO (2-3 minutes)
        # ======================
        logger.info("Running Nikto...")
        try:
            nikto_result = subprocess.run(
                ['nikto', '-h', target_url, '-Format', 'txt', '-Tuning', '123456789'],
                timeout=180,
                capture_output=True,
                text=True
            )
            
            if nikto_result.stdout:
                for line in nikto_result.stdout.split('\n'):
                    if line.startswith('+') and 'OSVDB' in line or 'Retrieved' in line or 'Server' in line:
                        all_findings.append({
                            'title': 'Nikto Vulnerability',
                            'risk_level': 'MEDIUM',
                            'business_impact': line.strip('+ ').strip(),
                            'technical_details': 'Detected by Nikto scanner',
                            'official_docs': ['https://cirt.net/Nikto2'],
                            'estimated_fix_time': '2-4 hours'
                        })
        
        except subprocess.TimeoutExpired:
            logger.error("Nikto timeout")
        except Exception as e:
            logger.error(f"Nikto error: {e}")
        
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
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        all_findings.sort(key=lambda x: severity_order.get(x['risk_level'], 4))
        
        top_3 = all_findings[:3]
        
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
        
        logger.info(f"Scan complete: {len(all_findings)} issues")
        
        return jsonify({
            'success': True,
            'vulnerabilities': top_3,
            'total_found': len(all_findings),
            'scan_info': {
                'url': target_url,
                'scan_id': scan_id,
                'timestamp': datetime.utcnow().isoformat(),
                'scanners_used': ['Mozilla Observatory', 'Nikto']
            }
        })
    
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return jsonify({'error': 'Scan failed'}), 500
