import sys
import traceback
import threading
import uuid
import tempfile
import subprocess
import os
import json
import re
import shutil
import urllib.request
import urllib.error
import urllib.robotparser
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, render_template
from scanner import scan_directory, scan_git_history
import db
import validators
import csv
import io
import hashlib

# Initialize the Flask web application instance
app = Flask(__name__)
# Dictionary to store background scan tasks mapped by a unique task_id

scan_tasks = {}
scan_tasks_lock = threading.Lock()

# Initialize the SQLite analytics database to store scan statistics

db.init_db()

# ------------------------------------------------------------------
# Severity classification
SEVERITY_MAP = {}
rules_path = os.path.join(os.path.dirname(__file__), 'rules.json')
if os.path.exists(rules_path):
    with open(rules_path, 'r', encoding='utf-8') as f:
        _rules = json.load(f)
        for _rule in _rules:
            sev = _rule.get('severity', 'MEDIUM')
            score = 4 if sev == 'CRITICAL' else 3 if sev == 'HIGH' else 2
            SEVERITY_MAP[_rule['name']] = {"level": sev, "score": score}

if not SEVERITY_MAP: # Fallback
    SEVERITY_MAP = {
        "AWS Secret Key (Generic 40-Char)": {"level": "CRITICAL", "score": 4},
        "GitHub PAT":                        {"level": "CRITICAL", "score": 4},
        "OpenAI API Key":                    {"level": "HIGH",     "score": 3},
        "Stripe API Key":                    {"level": "HIGH",     "score": 3},
        "Slack Token":                       {"level": "MEDIUM",   "score": 2},
        "Google API Key":                    {"level": "MEDIUM",   "score": 2},
    }

# ------------------------------------------------------------------
# 3. CUSTOM PATTERNS PERSISTENCE
# ------------------------------------------------------------------
CUSTOM_PATTERNS_FILE = os.path.join(os.path.dirname(__file__), 'custom_patterns.json')

def load_custom_patterns():
    if os.path.exists(CUSTOM_PATTERNS_FILE):
        try:
            with open(CUSTOM_PATTERNS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_custom_patterns(patterns):
    with open(CUSTOM_PATTERNS_FILE, 'w') as f:
        json.dump(patterns, f, indent=2)

# ------------------------------------------------------------------
# Task cleanup thread – deletes finished tasks after 30 min
def cleanup_old_tasks():
    while True:
        time.sleep(300)
        now = time.time()
        with scan_tasks_lock:
            to_delete = [
                tid for tid, task in scan_tasks.items()
                if task.get('status') != 'processing' and task.get('timestamp', 0) < now - 1800
            ]
            for tid in to_delete:
                del scan_tasks[tid]

threading.Thread(target=cleanup_old_tasks, daemon=True).start()

# ------------------------------------------------------------------
# Helper: update task progress (thread-safe)
def update_progress(task_id, **kwargs):
    with scan_tasks_lock:
        task = scan_tasks.get(task_id)
        if task:
            task.update(kwargs)

# ------------------------------------------------------------------
# Helper: robust temp directory removal for Windows long paths
def _safe_rmtree(path):
    """Remove a directory tree, handling Windows long paths and locked files."""
    if not os.path.exists(path):
        return
    try:
        # On Windows, use robocopy trick to handle long paths:
        # Create an empty dir, robocopy it over the target (deletes all files), then rmdir both
        if os.name == 'nt':
            empty_dir = tempfile.mkdtemp(prefix="empty_")
            subprocess.run(
                ['robocopy', empty_dir, path, '/MIR', '/R:1', '/W:1'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60
            )
            shutil.rmtree(path, ignore_errors=True)
            shutil.rmtree(empty_dir, ignore_errors=True)
        else:
            shutil.rmtree(path, ignore_errors=True)
    except Exception as e:
        print(f"[WARN] Temp cleanup failed (non-fatal): {e}", flush=True)

# ------------------------------------------------------------------
# Helper: clone a single repository
def clone_repo(repo_url, dest_dir, github_token, temp_dir, depth_args=None):
    """Clone a repo. depth_args controls clone depth (e.g. ['--depth','1','--single-branch'])."""
    if depth_args is None:
        depth_args = ['--depth', '1', '--single-branch']

    cmd = ['git', '-c', 'core.longpaths=true', 'clone'] + depth_args + [repo_url, dest_dir]
    env = os.environ.copy()

    if github_token:
        # Write a per-clone .netrc to avoid race conditions between threads
        netrc_dir = tempfile.mkdtemp(dir=temp_dir)
        netrc_path = os.path.join(netrc_dir, '.netrc')
        with open(netrc_path, 'w') as f:
            f.write(f"machine github.com login oauth2 password {github_token}\n")
        try:
            os.chmod(netrc_path, 0o600)
        except OSError:
            pass  # Windows doesn't support Unix permissions
        env['HOME'] = netrc_dir

    try:
        subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    except (subprocess.TimeoutExpired, Exception) as e:
        print(f"[WARN] Clone failed for {repo_url}: {e}")
    return dest_dir

# ------------------------------------------------------------------
# GitHub repository fetcher with pagination
def fetch_all_github_repos(username, token, include_forks=True):
    repos = []
    last_error = None

    # Build auth headers helper
    def make_headers(tok):
        headers = {"User-Agent": "SecretScanner/2.0"}
        if tok:
            # Fine-grained PATs (github_pat_*) need Bearer; classic PATs (ghp_*) work with both
            if tok.startswith("github_pat_"):
                headers["Authorization"] = f"Bearer {tok}"
            else:
                headers["Authorization"] = f"token {tok}"
        return headers

    # Pre-check rate limit
    try:
        rl_req = urllib.request.Request("https://api.github.com/rate_limit",
                                        headers=make_headers(token))
        with urllib.request.urlopen(rl_req, timeout=10) as rl_resp:
            rl_data = json.loads(rl_resp.read().decode())
            core = rl_data.get("resources", {}).get("core", {})
            remaining = core.get("remaining", "?")
            limit = core.get("limit", "?")
            print(f"[API] Rate limit: {remaining}/{limit} remaining")
            if remaining == 0:
                reset_ts = core.get("reset", 0)
                reset_in = max(0, reset_ts - int(time.time()))
                raise Exception(
                    f"GitHub API rate limit exhausted (0/{limit}). "
                    f"Resets in {reset_in // 60}m {reset_in % 60}s. "
                    f"Provide a valid GitHub Personal Access Token to get 5000 req/hr."
                )
    except urllib.error.URLError as e:
        print(f"[API] Rate limit check failed (non-fatal): {e}")

    for endpoint in [f"users/{username}/repos", f"orgs/{username}/repos"]:
        url = f"https://api.github.com/{endpoint}?per_page=100&page=1"
        print(f"[API] Trying: {url}", flush=True)
        endpoint_failed = False
        while url:
            req = urllib.request.Request(url, headers=make_headers(token))
            try:
                with urllib.request.urlopen(req, timeout=15) as response:
                    data = json.loads(response.read().decode())
                    if include_forks:
                        new_repos = [repo['clone_url'] for repo in data]
                    else:
                        new_repos = [repo['clone_url'] for repo in data if not repo.get('fork', False)]
                    repos.extend(new_repos)
                    print(f"[API] Got {len(new_repos)} repos from {url.split('?')[0]}", flush=True)
                    # Check for next page
                    url = None
                    link_header = response.headers.get('Link', '')
                    if link_header:
                        for part in link_header.split(','):
                            if 'rel="next"' in part:
                                url = part.split(';')[0].strip(' <>')
                                print(f"[API] Next page: {url}", flush=True)
                                break
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode('utf-8', errors='ignore')
                    detail = json.loads(body).get('message', '')
                except Exception:
                    detail = body[:200] if body else str(e)
                print(f"[API] HTTP {e.code} for {url}: {detail}", flush=True)

                if e.code in (404, 403):
                    # 404 = endpoint doesn't apply (e.g. orgs for a regular user)
                    # 403 = forbidden/rate-limited for THIS endpoint; try the other one
                    last_error = f"GitHub API error {e.code}: {detail}"
                    endpoint_failed = True
                    break
                else:
                    # 5xx or other errors — raise immediately
                    raise Exception(f"GitHub API error {e.code}: {detail}") from None
            except Exception as e:
                print(f"[API] Error for {url}: {e}", flush=True)
                last_error = str(e)
                endpoint_failed = True
                break

        # If the users endpoint succeeded and got repos, don't bother with orgs
        if not endpoint_failed and repos:
            break

    # If we got zero repos from all endpoints, raise the last error
    if not repos and last_error:
        raise Exception(f"Could not fetch repositories: {last_error}")

    print(f"[API] Total repos found: {len(repos)}", flush=True)
    return repos

# ------------------------------------------------------------------
# BFS web crawler (iterative)
def scrape_links_from_url(start_url: str, base_url: str, rp=None, max_pages=50):
    visited = set()
    from collections import deque
    queue = deque([start_url])
    found = []
    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        if rp and not rp.can_fetch('SecretScanner', url):
            continue
        req = urllib.request.Request(url, headers={'User-Agent': 'SecretScanner/2.0'})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                html = response.read().decode('utf-8', errors='ignore')
        except Exception:
            continue
        links = re.findall(r'href=["\']([^"\']*)["\']|src=["\']([^"\']*)["\']', html)
        for link_tuple in links:
            link = link_tuple[0] or link_tuple[1]
            if not link or link.startswith('#') or link.startswith('javascript:'):
                continue
            absolute = urljoin(url, link)
            if absolute.startswith(base_url) and absolute not in visited:
                found.append(absolute)
                queue.append(absolute)
    return list(set(found))

# ------------------------------------------------------------------
# Flask routes
# Main Route: Serves the SecretScanner User Interface
@app.route('/')
def index_neo():
    # Render the final version of the frontend (frontend_v3)
    return render_template('frontend_v3.html')



@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target', '').strip()
    target_type = data.get('type')
    
    if not target or target_type not in ['github', 'website']:
        return jsonify({'error': 'Invalid or missing target / type'}), 400
        
    task_id = str(uuid.uuid4())
    with scan_tasks_lock:
        scan_tasks[task_id] = {'status': 'processing', 'timestamp': time.time()}
    thread = threading.Thread(target=run_background_scan, args=(task_id, data))
    thread.start()
    return jsonify({'task_id': task_id})

@app.route('/result/<task_id>')
def get_result(task_id):
    with scan_tasks_lock:
        task = scan_tasks.get(task_id)
    if not task:
        return jsonify({'status': 'error', 'error': 'Task not found'})
    return jsonify(task)

# ------------------------------------------------------------------
# Triage: mark findings as false_positive / test / fix_later
@app.route('/triage', methods=['POST'])
def triage_finding():
    data = request.json
    task_id = data.get('task_id')
    finding_id = data.get('finding_id')
    action = data.get('action')  # false_positive, test, fix_later, open
    if action not in ('false_positive', 'test', 'fix_later', 'open'):
        return jsonify({'error': 'Invalid action'}), 400
    with scan_tasks_lock:
        task = scan_tasks.get(task_id)
        if not task or task.get('status') != 'ready':
            return jsonify({'error': 'Task not found or not ready'}), 404
        findings = task.get('result', {}).get('findings', [])
        for f in findings:
            if f.get('id') == finding_id:
                f['triage_status'] = action
                return jsonify({'ok': True, 'finding_id': finding_id, 'status': action})
    return jsonify({'error': 'Finding not found'}), 404

# ------------------------------------------------------------------
# Custom patterns CRUD
@app.route('/patterns', methods=['GET'])
def get_patterns():
    from config import SECRET_PATTERNS
    builtin = [{"name": k, "regex": v["regex"].pattern, "min_entropy": v["min_entropy"],
                "strict_mode": v["strict_mode"], "builtin": True} for k, v in SECRET_PATTERNS.items()]
    custom = load_custom_patterns()
    for c in custom:
        c["builtin"] = False
    return jsonify(builtin + custom)

@app.route('/patterns', methods=['POST'])
def add_pattern():
    data = request.json
    name = data.get('name', '').strip()
    regex = data.get('regex', '').strip()
    min_entropy = float(data.get('min_entropy', 3.0))
    strict_mode = bool(data.get('strict_mode', False))
    if not name or not regex:
        return jsonify({'error': 'Name and regex are required'}), 400
    try:
        re.compile(regex)
    except re.error as e:
        return jsonify({'error': f'Invalid regex: {e}'}), 400
    patterns = load_custom_patterns()
    if any(p['name'] == name for p in patterns):
        return jsonify({'error': 'Pattern name already exists'}), 409
    patterns.append({'name': name, 'regex': regex, 'min_entropy': min_entropy, 'strict_mode': strict_mode})
    save_custom_patterns(patterns)
    # Hot-reload into scanner
    _reload_custom_patterns()
    return jsonify({'ok': True, 'pattern': patterns[-1]})

@app.route('/patterns/<name>', methods=['DELETE'])
def delete_pattern(name):
    patterns = load_custom_patterns()
    patterns = [p for p in patterns if p['name'] != name]
    save_custom_patterns(patterns)
    _reload_custom_patterns()
    return jsonify({'ok': True})

def _reload_custom_patterns():
    """Hot-reload custom patterns into the scanner's config."""
    from config import SECRET_PATTERNS
    # Remove old custom patterns
    to_remove = [k for k in SECRET_PATTERNS if k.startswith('[Custom] ')]
    for k in to_remove:
        del SECRET_PATTERNS[k]
    # Add current custom patterns
    for p in load_custom_patterns():
        SECRET_PATTERNS[f"[Custom] {p['name']}"] = {
            'regex': re.compile(p['regex']),
            'min_entropy': p.get('min_entropy', 3.0),
            'strict_mode': p.get('strict_mode', False)
        }

# Load custom patterns on startup
_reload_custom_patterns()

# ------------------------------------------------------------------
# Export endpoints
@app.route('/api/analytics')
def get_analytics():
    return jsonify(db.get_analytics_summary())

@app.route('/export/<task_id>')
def export_results(task_id):
    fmt = request.args.get('format', 'json')
    with scan_tasks_lock:
        task = scan_tasks.get(task_id)
    if not task or task.get('status') != 'ready':
        return jsonify({'error': 'Task not found or not ready'}), 404
    findings = task.get('result', {}).get('findings', [])
    if fmt == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Type', 'Severity', 'Secret (Preview)', 'File', 'Line', 'Repository', 'Triage Status', 'Count'])
        for f in findings:
            for occ in f.get('occurrences', [{}]):
                writer.writerow([
                    f.get('type'), f.get('severity', 'MEDIUM'), f.get('preview'),
                    occ.get('file', ''), occ.get('line', ''), occ.get('repository', ''),
                    f.get('triage_status', 'open'), f.get('total_count', 1)
                ])
        resp = app.response_class(output.getvalue(), mimetype='text/csv')
        resp.headers['Content-Disposition'] = f'attachment; filename=secretscanner_report_{task_id[:8]}.csv'
        return resp
    else:
        return jsonify({
            'task_id': task_id,
            'scan_time': task.get('timestamp'),
            'mode': task.get('result', {}).get('mode'),
            'repos_scanned': task.get('result', {}).get('repos_scanned'),
            'total_findings': len(findings),
            'findings': findings
        })

# ------------------------------------------------------------------
# Pre-commit hook generator
PRECOMMIT_HOOK = '''#!/usr/bin/env python3
"""SecretScanner Pre-commit Hook — blocks commits containing secrets.
Generated by SecretScanner v1.0.
Bypass with: git commit --no-verify
"""
import subprocess, sys, re, math
from collections import Counter

PATTERNS = {
    "GitHub PAT":     r"(?i)\\b(ghp_[a-zA-Z0-9]{36})\\b",
    "OpenAI API Key": r"(?<![A-Za-z0-9_-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,160}|sk-[A-Za-z0-9]{48}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9_-])",
    "Slack Token":    r"(?i)\\b(xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24})\\b",
    "Stripe API Key": r"(?i)\\b(sk_(?:live|test)_[0-9a-zA-Z]{24,34})\\b",
    "Google API Key": r"(?<![A-Za-z0-9_])(AIza[0-9A-Za-z-_]{35})(?![A-Za-z0-9_])",
}
DUMMY = ["12345", "abcde", "qwerty", "dummy", "example", "placeholder", "xxxxx"]

def entropy(s):
    if not s: return 0
    c = Counter(s); n = len(s)
    return -sum((v/n) * math.log(v/n, 2) for v in c.values())

def main():
    result = subprocess.run(["git", "diff", "--cached", "--diff-filter=ACM", "-U0"], capture_output=True, text=True)
    blocked = []
    for line in result.stdout.splitlines():
        if not line.startswith("+") or line.startswith("+++"): continue
        for name, pattern in PATTERNS.items():
            for m in re.finditer(pattern, line):
                token = m.group(0)
                if entropy(token) < 3.0: continue
                if any(d in token.lower() for d in DUMMY): continue
                blocked.append((name, token[:20] + "..."))
    if blocked:
        print("\\n\\033[91m✖ SecretScanner: Secrets detected in staged changes!\\033[0m\\n")
        for name, preview in blocked:
            print(f"  \\033[93m⚠ {name}:\\033[0m {preview}")
        print("\\nRemove the secrets and try again.")
        print("To bypass: git commit --no-verify\\n")
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
'''

@app.route('/hook/download')
def download_hook():
    resp = app.response_class(PRECOMMIT_HOOK, mimetype='text/x-python')
    resp.headers['Content-Disposition'] = 'attachment; filename=pre-commit'
    return resp

# ------------------------------------------------------------------
# Background worker with three scan modes
# Background worker function to execute the scan asynchronously.
# Supports 3 modes: 'rapid', 'standard', 'deep'.
def run_background_scan(task_id, data):
    target_type = data.get('type')
    target = data.get('target', '').strip()
    repo_name = data.get('repo_name', '').strip()
    github_token = data.get('github_token', '').strip()
    include_forks = data.get('include_forks', True)
    mode = data.get('mode', 'standard')

    # Mode configuration
    if mode == 'deep':
        depth_args = []                               # full clone
        max_file_size = 0                             # no size limit
        max_pages = 200
    elif mode == 'standard':
        depth_args = ['--depth', '100']
        max_file_size = 20 * 1024 * 1024              # 20 MB
        max_pages = 50
    else:  # 'rapid'
        depth_args = ['--depth', '1', '--single-branch']
        max_file_size = 5 * 1024 * 1024               # 5 MB
        max_pages = 20

    repos_scanned = 0

    try:
        temp_dir = tempfile.mkdtemp(prefix="secretscan_")
        try:
            if target_type == 'github':
                if repo_name:
                    # Single repository
                    update_progress(task_id, stage='cloning', cloned_repos=0, total_repos=1)
                    clean_url = f"https://github.com/{target}/{repo_name}.git"
                    repo_dir = os.path.join(temp_dir, repo_name)
                    clone_repo(clean_url, repo_dir, github_token, temp_dir, depth_args)
                    repos_scanned = 1
                    update_progress(task_id, cloned_repos=1)
                else:
                    # Full user/org – fetch repo list then parallel clone
                    update_progress(task_id, stage='fetching', cloned_repos=0, total_repos=0)
                    repo_urls = fetch_all_github_repos(target, github_token, include_forks=include_forks)
                    total_repos = len(repo_urls)

                    if total_repos == 0:
                        update_progress(task_id, stage='cloning', cloned_repos=0, total_repos=0)
                    else:
                        update_progress(task_id, stage='cloning', cloned_repos=0, total_repos=total_repos)
                        with ThreadPoolExecutor(max_workers=5) as executor:
                            futures = {}
                            for idx, repo_url in enumerate(repo_urls):
                                # Extract real repo name from URL for display in results
                                url_path = repo_url.rstrip('/').rstrip('.git')
                                real_name = url_path.split('/')[-1] or f"repo_{idx}"
                                # Avoid directory name collisions (forks with same name)
                                repo_dir = os.path.join(temp_dir, f"{real_name}")
                                if os.path.exists(repo_dir):
                                    repo_dir = os.path.join(temp_dir, f"{real_name}_{idx}")
                                futures[executor.submit(clone_repo, repo_url, repo_dir, github_token, temp_dir, depth_args)] = repo_url
                            for future in as_completed(futures):
                                try:
                                    future.result()
                                except Exception as e:
                                    print(f"[WARN] Clone error: {futures[future]}: {e}")
                                repos_scanned += 1
                                update_progress(task_id, cloned_repos=repos_scanned)

            elif target_type == 'website':
                if not target.startswith('http'):
                    target = 'https://' + target
                parsed = urlparse(target)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                rp = urllib.robotparser.RobotFileParser()
                rp.set_url(urljoin(base_url, '/robots.txt'))
                try:
                    rp.read()
                except:
                    rp = None

                update_progress(task_id, stage='crawling', scraped_pages=0, total_pages=0)
                all_routes = [target] + scrape_links_from_url(target, base_url, rp, max_pages)
                total_routes = len(all_routes)
                update_progress(task_id, stage='scraping', scraped_pages=0, total_pages=total_routes)

                for idx, route in enumerate(all_routes):
                    req = urllib.request.Request(route, headers={'User-Agent': 'SecretScanner/2.0'})
                    try:
                        with urllib.request.urlopen(req, timeout=10) as response:
                            page_content = response.read().decode('utf-8', errors='ignore')
                        fake_file_path = os.path.join(temp_dir, f"scraped_route_{idx}.html")
                        with open(fake_file_path, "w", encoding="utf-8") as f:
                            f.write(f"<!-- {route} -->\n\n{page_content}")
                        repos_scanned += 1
                        update_progress(task_id, scraped_pages=repos_scanned, total_pages=total_routes)
                        crawl_delay = 0.1 if mode == 'rapid' else 0.3
                        time.sleep(crawl_delay)
                    except Exception:
                        continue

            # --- Run scanner ---
            # Throttled progress callback: update at most every 0.3s to avoid lock contention
            _last_progress_time = [0]
            _last_scanned = [0]
            _total_files_ref = [0]

            def progress_callback(scanned, total):
                _total_files_ref[0] = total
                _last_scanned[0] = scanned
                now = time.monotonic()
                # Update on first call, last call, or every 0.3s
                if scanned == 0 or scanned == total or now - _last_progress_time[0] >= 0.3:
                    _last_progress_time[0] = now
                    update_progress(task_id, stage='scanning', scanned_files=scanned, total_files=total)

            log_path = os.path.join(temp_dir, f"quarantine_{uuid.uuid4().hex[:8]}.log")
            raw_vulnerabilities = scan_directory(
                temp_dir, log_path=log_path, max_file_size=max_file_size,
                progress_callback=progress_callback, mode=mode
            )

            # Deep Git History Scanning
            if target_type == 'github' and mode in ['standard', 'deep']:
                for item in os.listdir(temp_dir):
                    repo_dir = os.path.join(temp_dir, item)
                    if os.path.isdir(os.path.join(repo_dir, ".git")):
                        history_vulns = scan_git_history(repo_dir, mode)
                        for hv in history_vulns:
                            # hv = (secret_name, token, file_info, line_num, severity)
                            fixed_path = os.path.join(item, hv[2])
                            raw_vulnerabilities.append((hv[0], hv[1], os.path.join(temp_dir, fixed_path), hv[3], hv[4]))

            # Ensure final count is pushed
            update_progress(task_id, stage='scanning',
                            scanned_files=_last_scanned[0], total_files=_total_files_ref[0])

            # Deduplicate and enrich
            deduped = {}
            for secret_type, token, full_path, line_num, severity in raw_vulnerabilities:
                clean_filepath = full_path.replace(temp_dir, "").replace("\\", "/")
                if clean_filepath.startswith("/"):
                    clean_filepath = clean_filepath[1:]

                current_repo = ""
                if target_type == 'github' and "/" in clean_filepath:
                    current_repo = clean_filepath.split("/")[0]
                elif target_type == 'website' and "scraped_route_" in clean_filepath:
                    try:
                        with open(full_path, 'r', encoding='utf-8') as sf:
                            first_line = sf.readline()
                            if first_line.startswith("<!--"):
                                source_url = first_line.replace("<!--", "").replace("-->", "").strip()
                                current_repo = source_url if source_url.startswith("http") else "Live Domain"
                    except:
                        current_repo = "Live Domain"

                preview = token
                if len(token) > 16:
                    preview = f"{token[:12]}...{token[-4:]}"

                # Deduplicate by token only, to merge Generic and Specific matches
                key = token
                if key not in deduped:
                    sev = SEVERITY_MAP.get(secret_type, {"level": "MEDIUM", "score": 2})
                    # Override default severity with dynamically calculated severity if higher
                    final_severity = severity if severity in ["CRITICAL", "HIGH"] else sev["level"]
                    deduped[key] = {
                        "type": secret_type,
                        "full_secret": token,
                        "preview": preview,
                        "severity": final_severity,
                        "severity_score": sev["score"] if final_severity != "CRITICAL" else 4,
                        "total_count": 0,
                        "triage_status": "open",
                        "occurrences": [],
                        "is_active": "untested",
                        "id": hashlib.md5(f"{secret_type}:{token}".encode()).hexdigest()[:12]
                    }
                else:
                    # If we already have this token as Generic, but we just found a more specific type, upgrade it
                    if deduped[key]["type"] == "Generic API Key" and secret_type != "Generic API Key":
                        deduped[key]["type"] = secret_type
                        sev = SEVERITY_MAP.get(secret_type, {"level": "MEDIUM", "score": 2})
                        final_severity = severity if severity in ["CRITICAL", "HIGH"] else sev["level"]
                        deduped[key]["severity"] = final_severity
                        deduped[key]["severity_score"] = sev["score"] if final_severity != "CRITICAL" else 4
                        deduped[key]["id"] = hashlib.md5(f"{secret_type}:{token}".encode()).hexdigest()[:12]

                deduped[key]["total_count"] += 1
                deduped[key]["occurrences"].append({
                    "file": clean_filepath,
                    "line": str(line_num),
                    "repository": current_repo
                })

            formatted_findings = list(deduped.values())

            # Async validation checks — ONLY for token types with known API endpoints.
            # This prevents the validator from blocking on thousands of un-validatable tokens.
            VALIDATABLE_TYPES = GLOBAL_VALIDATABLE_TYPES

            validatable = [f for f in formatted_findings if f["type"] in VALIDATABLE_TYPES]
            non_validatable = [f for f in formatted_findings if f["type"] not in VALIDATABLE_TYPES]

            # Mark non-validatable tokens instantly
            for f in non_validatable:
                f["is_active"] = "unknown"
                f["metadata"] = ""

            if validatable:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_finding = {
                        executor.submit(validators.validate_token, f["full_secret"], f["type"]): f 
                        for f in validatable
                    }
                    for future in as_completed(future_to_finding):
                        finding = future_to_finding[future]
                        try:
                            val_res = future.result()
                            finding["is_active"] = val_res.get("status", "unknown")
                            finding["metadata"] = val_res.get("metadata", "")
                        except Exception as e:
                            finding["is_active"] = "unknown"
                            finding["metadata"] = "Validation failed"

            # Save to SQLite Analytics Dashboard DB using batch insert
            db.record_scan_and_findings(
                task_id, mode, target_type, target, 
                repos_scanned, _total_files_ref[0], 
                time.time() - scan_tasks[task_id]['timestamp'], 
                formatted_findings
            )

            total_time = time.time() - scan_tasks[task_id]['timestamp']
            with scan_tasks_lock:
                scan_tasks[task_id] = {
                    'status': 'ready',
                    'result': {
                        'findings': formatted_findings,
                        'repos_scanned': repos_scanned,
                        'mode': mode,
                        'target_type': target_type,
                        'total_time': total_time
                    },
                    'timestamp': time.time()
                }
        finally:
            # Robust temp directory cleanup for Windows long paths
            _safe_rmtree(temp_dir)
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[ERROR] Scan failed: {e}\\n{tb}", flush=True)
        with scan_tasks_lock:
            scan_tasks[task_id] = {'status': 'error', 'error': str(e), 'timestamp': time.time()}

if __name__ == '__main__':
    def kill_zombies(port=5000):
        """Kill any stale processes still holding the target port."""
        try:
            result = subprocess.run(
                ['netstat', '-ano'], capture_output=True, text=True, timeout=5
            )
            pids_to_kill = set()
            for line in result.stdout.splitlines():
                if f':{port}' in line and 'LISTENING' in line:
                    parts = line.split()
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) != os.getpid():
                        pids_to_kill.add(int(pid))
            for pid in pids_to_kill:
                try:
                    subprocess.run(['taskkill', '/F', '/PID', str(pid)],
                                   capture_output=True, timeout=5)
                    print(f"[CLEANUP] Killed zombie process PID {pid} on port {port}")
                except Exception:
                    pass
        except Exception:
            pass

    kill_zombies()
    print("\\n" + "="*60)
    print("[*] SecretScanner v1.0")
    print("[*] Dashboard: http://127.0.0.1:5000")
    print("="*60 + "\\n")
    app.run(debug=False, port=5000)