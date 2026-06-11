import os
import mmap
import logging
import uuid
import re
import concurrent.futures
import subprocess
import zipfile
import tarfile
import tempfile
try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

# pyrefly: ignore [missing-import]
from config import (
    IGNORED_EXTENSIONS, IGNORED_DIRECTORIES, IGNORED_FILENAMES,
    IGNORED_SUBSTRINGS, IGNORED_SUFFIXES, SECRET_PATTERNS,
    DEEP_ONLY_EXTENSIONS, STANDARD_ONLY_EXTENSIONS
)
# pyrefly: ignore [missing-import]
from filters import (
    calculate_shannon_entropy,
    is_pure_hex_hash,
    is_uuid,
    is_dummy_placeholder,
    is_base64_human_text,
    is_natural_language_distribution,
    is_language_by_naive_bayes,
    is_uri_routing_parameter,
    has_valid_secret_context,
    is_programming_identifier
)

# ------------------------------------------------------------------
# Performance constants
DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024          # 5 MB – skip larger files
FAST_KEYWORDS = [
    'ghp_', 'sk-', 'xoxb', 'xoxp', 'xoxa', 'xoxr', 'AIza', 'AKIA',
                 'sk_live', 'sk_test', 'token', 'secret', 'api_key', 'password',
                 'bearer', 'auth', 'credentials', '-----BEGIN', 'RSA PRIVATE KEY']

_quarantine_logger = None

# ------------------------------------------------------------------
# Windows-safe quarantine logger
def setup_quarantine_logger(log_path: str):
    """Create a quarantine logger that handles Windows file locks by using unique names."""
    base, ext = os.path.splitext(log_path)
    for attempt in range(5):
        try:
            if os.path.exists(log_path):
                os.remove(log_path)
            break
        except PermissionError:
            log_path = f"{base}_{uuid.uuid4().hex[:6]}{ext}"
    logger = logging.getLogger(f'quarantine_{os.path.basename(log_path)}')
    logger.handlers.clear()
    log_dir = os.path.dirname(log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    handler = logging.FileHandler(log_path, mode='w', encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger

def log_to_quarantine(token: str, reason: str, filepath: str, logger=None):
    if logger:
        logger.debug(f"[QUARANTINE] Token: {token[:10]}... | Reason: {reason} | File: {filepath}")


import bisect

def build_line_index(content: str) -> list:
    return [i for i, c in enumerate(content) if c == '\n']

def get_line_number_fast(line_index: list, pos: int) -> int:
    return bisect.bisect_left(line_index, pos) + 1

_PREFILTER_RE = re.compile(
    '|'.join(re.escape(kw) for kw in FAST_KEYWORDS), re.IGNORECASE
)

def fast_prefilter(content: str) -> bool:
    """Quick keyword check – skip file if no secret-related keywords found."""
    return bool(_PREFILTER_RE.search(content))

def safe_extract(tar, path):
    for member in tar.getmembers():
        member_path = os.path.realpath(os.path.join(path, member.name))
        if not member_path.startswith(os.path.realpath(path) + os.sep):
            raise Exception(f"Path traversal attempt: {member.name}")
    tar.extractall(path)

def scan_archive(filepath: str, max_file_size: int, depth: int, mode: str, logger=None) -> list:
    findings = []
    MAX_UNCOMPRESSED = 50 * 1024 * 1024  # 50 MB limit to prevent zip bombs
    
    if depth > 3:
        return []
        
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            filepath_lower = filepath.lower()
            zip_exts = ('.zip', '.jar', '.war', '.ear', '.aar', '.apk', '.ipa')
            tar_exts = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz')
            sz_exts = ('.7z',)
            rar_exts = ('.rar',)
            
            if filepath_lower.endswith(zip_exts):
                with zipfile.ZipFile(filepath, 'r') as z:
                    total_size = sum(info.file_size for info in z.infolist())
                    if total_size > MAX_UNCOMPRESSED:
                        return []
                    z.extractall(temp_dir)
            elif filepath_lower.endswith(tar_exts):
                with tarfile.open(filepath, 'r:*') as t:
                    total_size = sum(m.size for m in t.getmembers() if m.isreg())
                    if total_size > MAX_UNCOMPRESSED:
                        return []
                    safe_extract(t, temp_dir)
            elif filepath_lower.endswith(sz_exts):
                if not HAS_PY7ZR:
                    return []
                try:
                    with py7zr.SevenZipFile(filepath, mode='r') as z:
                        total_size = sum(f.uncompressed for f in z.list() if f.uncompressed)
                        if total_size > MAX_UNCOMPRESSED:
                            return []
                        z.extractall(temp_dir)
                except Exception:
                    return []
            elif filepath_lower.endswith(rar_exts):
                if not HAS_RARFILE:
                    return []
                try:
                    with rarfile.RarFile(filepath) as rf:
                        total_size = sum(f.file_size for f in rf.infolist())
                        if total_size > MAX_UNCOMPRESSED:
                            return []
                        rf.extractall(temp_dir)
                except Exception:
                    return []
            else:
                return []
                
            for root, dirs, files in os.walk(temp_dir):
                dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIRECTORIES]
                for file in files:
                    fp = os.path.join(root, file)
                    res = scan_file(fp, max_file_size, depth + 1, mode, logger)
                    if res:
                        for r in res:
                            secret_name, token, fpath, line_num, severity = r
                            rel_path = os.path.relpath(fpath, temp_dir)
                            rel_path = rel_path.replace('\\', '/')
                            new_fp = f"{filepath} -> {rel_path}"
                            findings.append((secret_name, token, new_fp, line_num, severity))
            return findings
    except Exception as e:
        return []

def scan_file(filepath: str, max_file_size: int = DEFAULT_MAX_FILE_SIZE, depth: int = 0, mode: str = 'standard', logger=None):
    # Skip huge files (0 means no limit)
    try:
        fsize = os.path.getsize(filepath)
        if max_file_size > 0 and fsize > max_file_size:
            return None
        if fsize == 0:
            return None
    except OSError:
        return None

    # Get file metadata to check against our ignore-lists
    _, ext = os.path.splitext(filepath)
    basename = os.path.basename(filepath).lower()

    if mode == 'rapid':
        if ext.lower() in DEEP_ONLY_EXTENSIONS or ext.lower() in STANDARD_ONLY_EXTENSIONS:
            return None
    elif mode == 'standard':
        if ext.lower() in DEEP_ONLY_EXTENSIONS:
            return None

    zip_exts_set = {'.zip', '.jar', '.war', '.ear', '.aar', '.apk', '.ipa'}
    tar_exts_set = {'.tar', '.gz', '.tgz', '.bz2', '.tbz2', '.xz', '.txz'}
    sz_exts_set = {'.7z'}
    rar_exts_set = {'.rar'}
    
    if ext.lower() in zip_exts_set or ext.lower() in tar_exts_set or ext.lower() in sz_exts_set or ext.lower() in rar_exts_set:
        return scan_archive(filepath, max_file_size, depth, mode, logger)

    if ext.lower() in IGNORED_EXTENSIONS or basename in IGNORED_FILENAMES:
        return None
    if any(filepath.endswith(suffix) for suffix in IGNORED_SUFFIXES):
        return None
    if any(sub in basename for sub in IGNORED_SUBSTRINGS):
        return None

    try:
        with open(filepath, 'rb') as f:
            if fsize > 1024 * 1024:
                # Use mmap for large files (>1MB) for memory efficiency
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    content = mm.read().decode('utf-8', errors='ignore')
            else:
                # Direct read for smaller files – avoids mmap overhead
                content = f.read().decode('utf-8', errors='ignore')
    except Exception:
        return None

    # Fast pre-filter – keyword gate only
    if not fast_prefilter(content):
        return None

    findings = []
    line_index = build_line_index(content)
    for secret_name, cfg in SECRET_PATTERNS.items():
        for match in cfg["regex"].finditer(content):
            token = match.group(match.lastindex) if match.lastindex else match.group(0)
            line_num = get_line_number_fast(line_index, match.start())
            entropy = calculate_shannon_entropy(token)

            if entropy < cfg["min_entropy"]:
                log_to_quarantine(token, f"Entropy ({entropy:.2f}) < {cfg['min_entropy']}", filepath, logger=logger)
                continue
            if is_dummy_placeholder(token):
                log_to_quarantine(token, "Dummy placeholder", filepath, logger=logger)
                continue

            if is_programming_identifier(token):
                log_to_quarantine(token, "Programming identifier", filepath, logger=logger)
                continue

            if not cfg["strict_mode"]:
                severity = "HIGH"
                findings.append((secret_name, token, filepath, line_num, severity))
                continue

            # Strict mode cascade (AWS style)
            start = max(0, match.start() - 60)
            end = min(len(content), match.end() + 60)
            context = content[start:end]
            if is_uri_routing_parameter(token, context):
                log_to_quarantine(token, "URI param", filepath, logger=logger)
                continue

            if is_pure_hex_hash(token) or is_uuid(token):
                log_to_quarantine(token, "Hash/UUID", filepath, logger=logger)
                continue
            if is_base64_human_text(token):
                log_to_quarantine(token, "Base64 text", filepath, logger=logger)
                continue
            if is_natural_language_distribution(token):
                log_to_quarantine(token, "Language distribution", filepath, logger=logger)
                continue
            if is_language_by_naive_bayes(token):
                log_to_quarantine(token, "Trigram language", filepath, logger=logger)
                continue


            if not has_valid_secret_context(token, context):
                log_to_quarantine(token, "No assignment context", filepath, logger=logger)
                continue

            severity = "HIGH"
            findings.append((secret_name, token, filepath, line_num, severity))
    return findings

# Scans a directory for secrets iteratively, using mmap to read files efficiently.
# Ignores common false positive folders like .git and node_modules.
def scan_directory(target_dir: str, log_path: str = None, max_file_size: int = DEFAULT_MAX_FILE_SIZE, progress_callback = None, mode: str = 'standard') -> list:
    if not log_path:
        log_path = os.path.join(target_dir, f"quarantine_{uuid.uuid4().hex[:8]}.log")
    logger = setup_quarantine_logger(log_path)

    files_to_scan = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIRECTORIES]
        for file in files:
            if file.startswith("quarantine_") and file.endswith(".log"):
                continue
            if file in [".gitignore", ".gitattributes"]:
                continue
            files_to_scan.append(os.path.join(root, file))

    total_files = len(files_to_scan)
    print(f"[DEBUG] Scanning {total_files} files (size limit: {max_file_size // 1024 // 1024 if max_file_size > 0 else 'unlimited'} MB)")
    if progress_callback:
        progress_callback(0, total_files)

    all_findings = []
    scanned_files = 0
    max_workers = min(os.cpu_count() * 4, 32)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_file, fp, max_file_size, 0, mode, logger): fp
            for fp in files_to_scan
        }
        for future in concurrent.futures.as_completed(futures):
            scanned_files += 1
            if progress_callback:
                progress_callback(scanned_files, total_files)
            try:
                res = future.result()
                if res:
                    all_findings.extend(res)
            except Exception:
                pass
    if logger:
        for handler in logger.handlers[:]:
            handler.flush()
            handler.close()
            logger.removeHandler(handler)
    return all_findings
# Scans the git history using subprocess calls to git log and git diff.
# Captures secrets that might have been pushed and later deleted.
def scan_git_history(repo_dir: str, mode: str, progress_callback=None) -> list:
    if mode == 'rapid':
        return []
        
    cmd = ['git', 'log', '-p', '--no-merges', '-E', '--author=^(?!.*(dependabot|github-actions))']
    if mode == 'standard':
        cmd.extend(['-n', '100'])
    elif mode == 'deep':
        cmd.extend(['--all'])
        
    try:
        proc = subprocess.Popen(cmd, cwd=repo_dir, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8', errors='ignore')
    except Exception:
        return []

    findings = []
    current_commit = ""
    current_file = ""
    
    for line in proc.stdout:
        if line.startswith('commit '):
            current_commit = line.split()[1]
        elif line.startswith('+++ b/'):
            current_file = line[6:].strip()
        elif line.startswith('+') and not line.startswith('+++'):
            content = line[1:]
            if not fast_prefilter(content):
                continue
                
            for secret_name, cfg in SECRET_PATTERNS.items():
                for match in cfg["regex"].finditer(content):
                    token = match.group(0)
                    entropy = calculate_shannon_entropy(token)
                    if entropy < cfg["min_entropy"]: continue
                    if is_dummy_placeholder(token): continue
                    
                    if cfg["strict_mode"]:
                        if is_pure_hex_hash(token) or is_uuid(token): continue
                        if is_base64_human_text(token): continue
                        if is_natural_language_distribution(token): continue
                        if is_language_by_naive_bayes(token): continue
                        if not has_valid_secret_context(token, content): continue
                    
                    severity = "HIGH"
                    if secret_name == "OAuth Client Secret":
                        if "client_id" in content.lower() or "clientid" in content.lower():
                            severity = "CRITICAL"
                        else:
                            severity = "MEDIUM"
                    elif secret_name == "OAuth Client ID":
                        severity = "MEDIUM"

                    findings.append((secret_name, token, f"{current_file} (commit: {current_commit[:8]})", "history", severity))
                    
    proc.stdout.close()
    proc.wait()
    return findings