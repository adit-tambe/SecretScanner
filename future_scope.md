# 🚀 Future Scope & Roadmap: SecretScanner

This document serves as a backlog of ideas, feature expansions, and technical debts to tackle if/when we return to this project. 

### 1. Restoring the 500+ Scraped Rules
During the initial build, over 500 API key names were successfully scraped from documentation, but their mathematical regex formulas were missing (resulting in blank regex fields in `rules.json`). 
- **Action:** Systematically hunt down the open-source regex rulesets (e.g., from TruffleHog or Gitleaks source code) that map to these 500 names.
- **Goal:** Expand the pre-compiled regex engine to support a massive catalog of niche and obscure API keys without sacrificing the O(n) pre-filter performance.

### 2. AI-Powered Contextual Verification
Currently, context verification looks for assignment operators (`=`, `:`) and keywords (`key`, `password`) within a 120-character window.
- **Action:** Integrate a lightweight local LLM (like Llama-3-8B or Phi-3) to act as a secondary verification agent. 
- **Goal:** When the engine flags a high-entropy string, pass the surrounding code chunk to the LLM to ask: *"Is this an active cryptographic key, or just a dummy variable in a test file?"* This would bring false positives down to absolute zero.

### 3. Visual Regex Builder UI
Right now, adding a custom pattern requires manually editing JSON and ensuring the regex doesn't trigger Catastrophic Backtracking.
- **Action:** Build a visual "Regex Sandbox" directly into the 3D dashboard.
- **Goal:** Allow users to type in sample keys, auto-generate strict regex bounds, test them against simulated code, and calculate their average Shannon Entropy before saving them to `custom_patterns.json`.

### 4. Advanced Obfuscation Detection
Bad actors (or clever developers) sometimes try to hide keys using encoding layers. Our current engine detects base64 encoding.
- **Action:** Expand the heuristics decoder.
- **Goal:** Detect multi-layer obfuscation (e.g., Base64 encoded *twice*, Hex-encoded strings, XOR encoding, or keys broken across multiple concatenated string variables like `key = "sk-" + "proj-" + "123"`).

### 5. Automated CI/CD Integration (GitHub Actions)
The tool currently runs locally via a Flask server or a git pre-commit hook.
- **Action:** Package the engine into a standalone Docker container.
- **Goal:** Create a GitHub Action that automatically runs SecretScanner on every Pull Request. If a secret is detected, it instantly blocks the merge and leaves an automated review comment highlighting the specific line of code.

### 6. Secrets Honeypot (Offensive Defense)
Since scrapers are actively hunting for keys, we can fight back.
- **Action:** Build a "Tripwire Generator" module.
- **Goal:** Generate highly-entropic, perfectly formatted *fake* API keys (e.g., a dummy AWS key). The user can intentionally leave these in public repositories. If a bad actor scrapes and attempts to use the fake key, the scanner logs their IP address and flags them. 

### 7. Frontend Web Worker Offloading
The 3D WebGL interface powered by Three.js is beautiful but can be heavy.
- **Action:** Offload the GSAP animations and Three.js physics calculations to JavaScript Web Workers.
- **Goal:** Ensure the dashboard runs at a buttery smooth 144fps even on low-end laptops while the background Python daemon is chewing through heavy I/O operations.
