import math
import re
import base64
from collections import Counter

TRIGRAM_LOG_LIKELIHOOD = {
    'the': 3.5, 'and': 3.2, 'ing': 3.4, 'ion': 3.1, 'ent': 3.0, 'ati': 2.9, 'for': 2.8,
    'ter': 2.7, 'est': 2.6, 'ers': 2.5, 'tha': 2.4, 'res': 2.6, 'thi': 2.5, 'und': 2.3,
    'get': 3.3, 'set': 3.3, 'cre': 3.1, 'ate': 3.2, 'upd': 3.0, 'dat': 3.1, 'str': 2.9,
    'int': 2.8, 'val': 2.9, 'nam': 3.2, 'url': 3.0, 'uid': 2.7, 'req': 2.9, 'res': 2.8,
    'api': 3.1, 'key': 3.0, 'tok': 2.9, 'aut': 3.0, 'use': 3.1, 'pwd': 2.5, 'env': 2.8,
    'con': 2.7, 'obj': 2.6, 'arr': 2.5, 'fun': 2.8, 'ret': 2.9, 'def': 2.7, 'cla': 2.6,
    'ide': 2.8, 'den': 2.7, 'tif': 2.6, 'fie': 2.5, 'wid': 2.8, 'idt': 2.4, 'dth': 2.5,
    'vis': 2.9, 'isb': 2.3, 'ble': 2.6, 'asc': 2.7, 'sce': 2.5, 'cen': 2.6, 'end': 2.5,
    'des': 2.8, 'cri': 2.6, 'ban': 2.3, 'ner': 2.4, 'log': 2.7, 'sta': 2.8, 'tus': 2.7,
    'loc': 2.6, 'pub': 2.5, 'fon': 2.4, 'tex': 2.5, 'liv': 2.3, 'mat': 2.5, 'inn': 2.4
}

# -------------------------------------------------------------------------
# 1. SHANNON ENTROPY (Math for "How random is this?")
# -------------------------------------------------------------------------
def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())

# -------------------------------------------------------------------------
# 2. STRING PATTERN MATCHERS
# -------------------------------------------------------------------------
def is_pure_hex_hash(data: str) -> bool:
    """Checks if the string is just a generic Hex Hash (like MD5 or SHA). These are rarely secrets."""
    if len(data) in (32, 40, 64) and re.match(r'^[0-9a-fA-F]+$', data):
        return True
    return False

def is_uuid(data: str) -> bool:
    """Checks if the string is a standard UUID (like 123e4567-e89b-12d3-a456-426614174000)."""
    return bool(re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', data))

def is_dummy_placeholder(data: str) -> bool:
    """Checks if the developer explicitly typed 'your-api-key-here'."""
    lower_data = data.lower()
    placeholders = [
        'placeholder', 'example', 'your_api_key', 'your-api-key', 'your_token',
        'insert_key_here', 'replace_me', 'dummy', 'xxxx', 'test_key', 'test-key'
    ]
    return any(p in lower_data for p in placeholders)

def is_base64_human_text(data: str) -> bool:
    """
    Sometimes developers encode normal sentences in Base64 (which looks like random gibberish).
    This function tries to decode it. If it turns into plain English, we know it's not a secret.
    """
    try:
        if len(data) % 4 != 0:
            return False
        decoded = base64.b64decode(data, validate=True).decode('utf-8')
        if re.search(r'[a-zA-Z]{5,}', decoded) and calculate_shannon_entropy(decoded) < 3.5:
            return True
        return False
    except Exception:
        pass
    return False

def is_natural_language_distribution(token: str) -> bool:
    """Only used for strict_mode patterns (unstructured keys like AWS).
    Detects tokens that look like concatenated English words rather than random keys.
    Must be conservative: random keys with mixed-case letters can accidentally
    hit vowel ratios of 0.20-0.30, so we require stronger evidence.
    """
    token_lower = token.lower()
    vowels = sum(1 for c in token_lower if c in 'aeiou')
    letters = sum(1 for c in token_lower if c.isalpha())
    if letters == 0:
        return False
    vowel_ratio = vowels / letters

    # Natural language tokens are almost entirely alphabetic (85%+),
    # have a vowel ratio in the core English range (0.25-0.45),
    # and have LOW entropy (< 4.5) because real words reuse characters.
    # Random keys typically have entropy > 4.5 even when mostly alphabetic.
    if len(token) >= 30 and letters > (len(token) * 0.85):
        if 0.25 <= vowel_ratio <= 0.45:
            entropy = calculate_shannon_entropy(token)
            if entropy < 4.5:
                return True
    return False

def is_language_by_naive_bayes(token: str) -> bool:
    token_lower = token.lower()
    total_score = 0.0
    total_trigrams = len(token_lower) - 2
    if total_trigrams <= 0:
        return False
    for i in range(total_trigrams):
        trigram = token_lower[i:i+3]
        if trigram in TRIGRAM_LOG_LIKELIHOOD:
            total_score += TRIGRAM_LOG_LIKELIHOOD[trigram]
        else:
            total_score -= 1.5 if any(c in trigram for c in '+/=') else 0.25
    return (total_score / total_trigrams) > 0.60

def is_uri_routing_parameter(token: str, context_window: str) -> bool:
    window_lower = context_window.lower()
    token_lower = token.lower()
    # Direct path context: token appears inside a URL-like path
    if f"/{token_lower}/" in window_lower or f"/{token_lower}?" in window_lower:
        return True
    # Token is preceded or followed by a slash (it's part of a URL path segment)
    token_start = window_lower.find(token_lower)
    if token_start > 0 and window_lower[token_start - 1] == '/':
        return True
    if token_start >= 0:
        token_end = token_start + len(token_lower)
        if token_end < len(window_lower) and window_lower[token_end] == '/':
            return True
    # Known route/asset keywords preceding the token
    route_keywords = ['assets/', 'drive/', 'status/', 'issues/', 'p/', 'id/', 'd/', 'commits/',
                      'releases/', 'download/', 'blob/', 'tree/', 'raw/', 'archive/', 'tags/',
                      'packages/', 'v1/', 'v2/', 'v3/', 'api/', 'dist/', 'cdn/']
    if any(f"{keyword}{token_lower}" in window_lower for keyword in route_keywords):
        return True
    # URL-like context: http(s) or www or .com/.org/.io in the window near the token
    url_indicators = ['http://', 'https://', 'www.', '.com/', '.org/', '.io/', '.net/', '.dev/']
    if any(ind in window_lower for ind in url_indicators):
        return True
    # Maven/package coordinate pattern: e.g. com/xianyi/OpenBLAS
    if re.search(r'[a-z]+/[a-z0-9_-]+/[A-Za-z0-9_-]+/', window_lower):
        return True
    return False

def is_programming_identifier(token: str) -> bool:
    # Remove common path prefixes or file extensions before checking
    clean_token = re.sub(r'^[a-z0-9_]+/', '', token)
    clean_token = re.sub(r'\.[a-z0-9]+$', '', clean_token)
    
    if not clean_token.isalnum():
        return False
        
    camel_transitions = len(re.findall(r'[a-z][A-Z]', clean_token))
    # Mangled C++ / Swift names often have multiple numeric boundaries too like ZN5swift19Mutex
    numeric_transitions = len(re.findall(r'[A-Za-z][0-9]+[A-Z]', clean_token))
    
    if camel_transitions + numeric_transitions >= 4:
        # A real programming identifier usually has entropy < 4.6 (due to repeated letters in words)
        # Random base64 keys often hit 4+ transitions by chance, but have higher entropy.
        if calculate_shannon_entropy(clean_token) < 4.6:
            return True
    return False

def has_valid_secret_context(token: str, context_window: str) -> bool:
    window_lower = context_window.lower()
    if "integrity" in window_lower and "sha" in window_lower:
        return False
    if "data:image" in window_lower or "base64," in window_lower:
        return False
    if re.search(r'matrix3d?\s*\(', window_lower) or re.search(r'transform\s*:', window_lower):
        return False
    # Path indicators – NOT import/require
    path_indicators = ['href=', 'src=', 'url(', '../', './']
    if any(path in window_lower for path in path_indicators):
        return False
    # Duplicate occurrence check (case‑insensitive)
    if window_lower.count(token.lower()) > 1:
        return False
    intent_keywords = ['=', ':', 'secret', 'key', 'token', 'api', 'pass', 'bearer', 'auth', 'aws', 'client', 'env']
    return any(keyword in window_lower for keyword in intent_keywords)