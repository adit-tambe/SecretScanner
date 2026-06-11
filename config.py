"""
SecretScanner Engine - Configuration (config.py)

WHAT THIS FILE DOES:
This file holds lists of things the scanner should completely ignore.
If we scan image files, `.pdf` files, or the `.git` directory itself, 
the scanner would be incredibly slow and generate hundreds of "false positives" 
(things that look like secrets but aren't).

HOW IT WORKS (For Beginners):
When `scanner.py` looks at a file, it first checks these lists. 
If the file ends with `.jpg` or is named `package-lock.json`, the scanner skips it instantly.
"""

import os
import re
import json

IGNORED_EXTENSIONS = {
    # --- Images & Graphics ---
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.heic', '.raw', '.dng',
    '.psd', '.ai', '.indd', '.sketch', '.fig', '.xd', '.tga', '.pcx', '.exr', '.hdr',

    # --- Videos & Animations ---
    '.mp4', '.avi', '.mov', '.wmv', '.mkv', '.webm', '.m4v', '.flv', '.vob', '.ogv', '.3gp', '.3g2', '.mts', '.m2ts', '.ts',

    # --- Audio & Sound ---
    '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.wma', '.aac', '.alac', '.aiff', '.au', '.mid', '.midi', '.mka',

    # --- 3D & CAD Models ---
    '.obj', '.fbx', '.3ds', '.dae', '.blend', '.max', '.stl', '.ply', '.gltf', '.glb',

    # --- Documents & Presentations ---
    '.pdf', '.doc', '.docx', '.dot', '.dotx', '.docm', '.xls', '.xlsx', '.xlsb', '.xlsm', '.xltx',
    '.ppt', '.pptx', '.pot', '.potx', '.pps', '.ppsx', '.odt', '.ods', '.odp', '.rtf', '.epub', '.mobi',
    '.pages', '.key', '.numbers',

    # --- Archives & Compression ---
    # Removed .zip, .tar, .gz, .tgz, .bz2, .tbz2, .xz, .txz, .jar, .war, .ear, .aar, .apk, .ipa from ignore list so we can scan inside them!
    # Removed .rar and .7z for Deep mode extraction.
    '.zstd', '.zst',
    '.apks', '.xapk', '.dmg', '.pkg', '.deb', '.rpm',
    '.cab', '.msi', '.msu', '.cpio', '.dump',

    # --- Fonts ---
    '.ttf', '.otf', '.woff', '.woff2', '.eot', '.pfb', '.pfm', '.fon', '.fnt',

    # --- Compiled / Binaries ---
    '.exe', '.dll', '.so', '.dylib', '.class', '.pyc', '.pyo', '.pyd', '.o', '.a', '.lib', '.bin', '.dat',
    '.elc', '.luac', '.wasm',

    # --- Database & Serialization (Binary formats) ---
    # Removed .sqlite, .sqlite3, .db, .db3 because databases often contain plaintext passwords and API keys in their tables!
    '.mdb', '.accdb', '.parquet', '.avro', '.pickle', '.pkl', '.frm', '.ibd',

    # --- Disk Images & Virtual Machines ---
    '.iso', '.img', '.vdi', '.vmdk', '.qcow2', '.ova', '.ovf', '.vhdx',

    # --- Miscellaneous Non-Text / System ---
    '.DS_Store', '.min.js', '.min.css'
}

# -------------------------------------------------------------------------
# 2. IGNORED DIRECTORIES
# -------------------------------------------------------------------------
# If the scanner sees a folder with any of these names, it will not look inside it.
# `.git` contains huge amounts of internal version control data.
# `node_modules` contains millions of lines of open-source library code (we only care about user code).
IGNORED_DIRECTORIES = {
    '.git', '.svn', '.hg', 'node_modules', 'venv', '.venv', 'env', '.env_dir',
    '__pycache__', 'build', 'dist', 'target', 'out', 'bin', 'obj', 'vendor',
    'bower_components', 'coverage', '.next', '.nuxt', '.cache'
}

# -------------------------------------------------------------------------
# 3. IGNORED FILENAMES
# -------------------------------------------------------------------------
# Exact file names that are safe to skip. 
# Lockfiles (like `package-lock.json`) are auto-generated and huge. They slow down scanning.
IGNORED_FILENAMES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Gemfile.lock', 'composer.lock',
    'Cargo.lock', 'poetry.lock', 'go.sum', 'mix.lock', 'requirements.txt',
    '.gitignore', '.npmignore', '.dockerignore', 'LICENSE', 'README.md', 'CHANGELOG.md'
}

# -------------------------------------------------------------------------
# 4. IGNORED SUBSTRINGS
# -------------------------------------------------------------------------
# Substrings in filenames that indicate test/mock files which are usually ignored.
IGNORED_SUBSTRINGS = {
    '.test.', '.spec.', '.mock.'
}

# -------------------------------------------------------------------------
# 5. IGNORED SUFFIXES
# -------------------------------------------------------------------------
# Multi-part suffixes that splitext alone cannot catch.
IGNORED_SUFFIXES = {
    '.min.js', '.min.css'
}

# -------------------------------------------------------------------------
# 6. MODE-SPECIFIC EXTENSIONS
# -------------------------------------------------------------------------
# Extensions ONLY scanned in 'deep' mode (ignored in standard/rapid)
DEEP_ONLY_EXTENSIONS = {
    '.sqlite', '.sqlite3', '.db', '.db3', # Databases
    '.rar', '.7z' # Third-party archives
}

# Extensions ONLY scanned in 'standard' or 'deep' mode (ignored in rapid)
STANDARD_ONLY_EXTENSIONS = {
    '.zip', # Standard zips
    '.jar', '.war', '.ear', '.aar', '.apk', '.ipa',  # Compiled mobile/java archives
    '.tar', '.gz', '.tgz', '.bz2', '.tbz2', '.xz', '.txz', # Tarballs
}

import json
import os

SECRET_PATTERNS = {}

# Load dynamic rules
rules_path = os.path.join(os.path.dirname(__file__), 'rules.json')
if os.path.exists(rules_path):
    with open(rules_path, 'r', encoding='utf-8') as f:
        rules = json.load(f)
        for rule in rules:
            if rule.get('regex'):
                try:
                    SECRET_PATTERNS[rule['name']] = {
                        "regex": re.compile(rule['regex']),
                        "strict_mode": False,
                        "min_entropy": 3.0,
                        "id": rule['id']
                    }
                except re.error:
                    pass

# Fallbacks for specific known rules if they weren't in JSON
if "AWS Secret Key (Generic 40-Char)" not in SECRET_PATTERNS:
    SECRET_PATTERNS["AWS Secret Key (Generic 40-Char)"] = {
        "regex": re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
        "strict_mode": True,
        "min_entropy": 4.5,
        "id": "aws_secret_access_key"
    }