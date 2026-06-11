import urllib.request
import json
import logging
from urllib.error import URLError, HTTPError

# Timeout for all external validation requests to ensure performance constraints
VALIDATION_TIMEOUT = 3.0

def validate_github_token(token):
    """Check if a GitHub PAT is active and fetch its user metadata."""
    req = urllib.request.Request("https://api.github.com/user")
    req.add_header("Authorization", f"token {token}")
    req.add_header("User-Agent", "SecretScanner-v1.0")
    
    try:
        with urllib.request.urlopen(req, timeout=VALIDATION_TIMEOUT) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                username = data.get("login", "Unknown")
                return {"status": "active", "metadata": f"Owner: {username}"}
    except HTTPError as e:
        if e.code == 401:
            return {"status": "inactive", "metadata": "Token is revoked or invalid"}
        return {"status": "unknown", "metadata": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": "unknown", "metadata": "Connection timeout"}
    
    return {"status": "unknown", "metadata": ""}

def validate_stripe_token(token):
    """Check if a Stripe API Key is active and fetch its mode."""
    req = urllib.request.Request("https://api.stripe.com/v1/charges")
    # Basic auth with token as username, blank password
    import base64
    auth_str = f"{token}:"
    b64_auth = base64.b64encode(auth_str.encode('ascii')).decode('ascii')
    req.add_header("Authorization", f"Basic {b64_auth}")
    
    try:
        with urllib.request.urlopen(req, timeout=VALIDATION_TIMEOUT) as response:
            # Even if it succeeds without params, it means the key is valid
            return {"status": "active", "metadata": "Mode: Live/Test"}
    except HTTPError as e:
        if e.code == 401:
            return {"status": "inactive", "metadata": "Invalid API Key"}
        elif e.code == 400:
            # A 400 means the key is valid but the request is missing params
            mode = "Test" if "test" in token else "Live"
            return {"status": "active", "metadata": f"Mode: {mode}"}
        return {"status": "unknown", "metadata": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": "unknown", "metadata": "Connection timeout"}
    
    return {"status": "unknown", "metadata": ""}

def validate_openai_token(token):
    """Check if an OpenAI API Key is active."""
    req = urllib.request.Request("https://api.openai.com/v1/models")
    req.add_header("Authorization", f"Bearer {token}")
    
    try:
        with urllib.request.urlopen(req, timeout=VALIDATION_TIMEOUT) as response:
            if response.status == 200:
                return {"status": "active", "metadata": "Token is valid and active"}
    except HTTPError as e:
        if e.code == 401:
            return {"status": "inactive", "metadata": "Invalid or revoked API Key"}
        return {"status": "unknown", "metadata": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": "unknown", "metadata": "Connection timeout"}
    
    return {"status": "unknown", "metadata": ""}

def validate_slack_token(token):
    """Check if a Slack Token is active."""
    req = urllib.request.Request("https://slack.com/api/auth.test")
    req.add_header("Authorization", f"Bearer {token}")
    
    try:
        with urllib.request.urlopen(req, timeout=VALIDATION_TIMEOUT) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                if data.get("ok"):
                    return {"status": "active", "metadata": f"Team: {data.get('team', 'Unknown')}"}
                else:
                    return {"status": "inactive", "metadata": data.get("error", "invalid_auth")}
    except HTTPError as e:
        return {"status": "unknown", "metadata": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": "unknown", "metadata": "Connection timeout"}
    
    return {"status": "unknown", "metadata": ""}

def validate_google_token(token):
    """Check if a Google API Key is valid and test common services."""
    endpoints = {
        "Books": f"https://www.googleapis.com/books/v1/volumes?q=test&key={token}",
        "Gemini": f"https://generativelanguage.googleapis.com/v1beta/models?key={token}",
        "YouTube": f"https://www.googleapis.com/youtube/v3/videos?part=snippet&chart=mostPopular&key={token}",
        "Custom Search": f"https://customsearch.googleapis.com/customsearch/v1?q=test&key={token}",
        "Translation": f"https://translation.googleapis.com/language/translate/v2?q=hello&target=es&key={token}",
        "PageSpeed Insights": f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://google.com&key={token}",
        "Maps Geocoding": f"https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key={token}"
    }

    enabled_apis = []
    is_valid = False
    is_invalid = False
    
    for name, url in endpoints.items():
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=VALIDATION_TIMEOUT) as response:
                if response.status == 200:
                    body = response.read().decode()
                    if name == "Maps Geocoding":
                        try:
                            data = json.loads(body)
                            if data.get("status") == "REQUEST_DENIED":
                                msg = data.get("error_message", "").lower()
                                if "invalid" in msg:
                                    is_invalid = True
                                    break
                                elif "not authorized" in msg and "project" in msg:
                                    is_valid = True
                                else:
                                    is_valid = True
                                    enabled_apis.append(f"{name} (Restricted)")
                            else:
                                is_valid = True
                                enabled_apis.append(name)
                        except Exception:
                            is_valid = True
                    else:
                        is_valid = True
                        enabled_apis.append(name)
        except HTTPError as e:
            if e.code == 400:
                try:
                    error_data = json.loads(e.read().decode())
                    msg = error_data.get("error", {}).get("message", "")
                    if "API key not valid" in msg:
                        is_invalid = True
                        break # Key is completely invalid
                except Exception:
                    pass
            elif e.code == 403:
                is_valid = True
                try:
                    error_data = json.loads(e.read().decode())
                    reasons = []
                    for detail in error_data.get("error", {}).get("details", []):
                        if "reason" in detail:
                            reasons.append(detail["reason"])
                    for err in error_data.get("error", {}).get("errors", []):
                        if "reason" in err:
                            reasons.append(err["reason"])
                            
                    restricted_reasons = ["API_KEY_IP_ADDRESS_BLOCKED", "API_KEY_HTTP_REFERRER_BLOCKED", 
                                          "API_KEY_ANDROID_APP_BLOCKED", "API_KEY_IOS_APP_BLOCKED", "BILLING_DISABLED"]
                    if any(r in restricted_reasons for r in reasons):
                        enabled_apis.append(f"{name} (Restricted)")
                except Exception:
                    pass
        except Exception:
            pass
            
    if is_invalid:
        return {"status": "inactive", "metadata": "API Key is invalid"}
        
    if is_valid:
        if enabled_apis:
            return {"status": "active", "metadata": f"Active APIs: {', '.join(enabled_apis)}"}
        else:
            return {"status": "active", "metadata": "Valid key (No common APIs enabled)"}
            
    return {"status": "unknown", "metadata": "Could not determine status"}

def validate_token(token, secret_type):
    """Main entrypoint for token validation. Routes to specific functions."""
    secret_type_lower = secret_type.lower()
    
    if "github" in secret_type_lower and ("token" in secret_type_lower or "pat" in secret_type_lower):
        return validate_github_token(token)
    elif "stripe" in secret_type_lower:
        return validate_stripe_token(token)
    elif "openai" in secret_type_lower:
        return validate_openai_token(token)
    elif "slack" in secret_type_lower:
        return validate_slack_token(token)
    elif "google" in secret_type_lower:
        return validate_google_token(token)
    
    # Default fallback for un-validatable tokens
    return {"status": "unknown", "metadata": "Validation not supported for this type"}
