# 🛡️ Phishing URL Detector

![Educational Project](https://img.shields.io/badge/Project-Educational-blue.svg)
![Cybersecurity](https://img.shields.io/badge/Topic-Cybersecurity-success.svg)
![Dependencies](https://img.shields.io/badge/Dependencies-None-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Overview

The Phishing URL Detector is a lightweight, client-side tool designed to analyze web addresses for common characteristics found in phishing attacks. Phishing remains one of the most prevalent and dangerous cyber threats, tricking users into handing over sensitive credentials. This tool aims to educate users by breaking down the anatomy of malicious URLs and providing real-time risk assessments.

## Features

- **Real-time URL Analysis**: Instantly evaluates URLs without needing a backend server.
- **Risk Scoring System**: Calculates an overall risk score from 0 to 100 based on various heuristics.
- **Detailed Explanations**: Explains exactly *why* a URL triggered a warning.
- **Example Driven**: Includes safe and malicious examples for users to test.
- **10 Detection Heuristics**: Analyzes length, keywords, TLDs, IP usage, and more.
- **Educational Section**: Provides tips on how to manually spot phishing attempts.
- **Zero Dependencies**: Built with pure HTML, CSS, and JavaScript.

## Project Structure

```text
phishing-url-detector/
├── README.md                          # Project documentation
├── chrome-extension/                  # Chrome browser extension
│   ├── manifest.json                  # Extension configuration (Manifest V3)
│   ├── detector.js                    # Core detection engine (shared)
│   ├── content.js                     # Page scanner & link highlighter
│   ├── background.js                  # Badge & tab management
│   ├── popup.html                     # Extension popup UI
│   ├── popup.css                      # Popup styling (dark theme)
│   ├── popup.js                       # Popup interaction logic
│   └── icons/
│       ├── icon.svg                   # Vector icon source
│       └── README.md                  # Icon generation instructions
└── website/
    └── index.html                     # Standalone web app (HTML/CSS/JS)
```

## Screenshots

> *Add screenshots here* (e.g., of the extension popup, the website UI, safe vs dangerous results)

## Getting Started

No installations needed — everything runs client-side with zero dependencies!

### Part 1: Loading the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** using the toggle in the top-right corner
3. Click **Load unpacked**
4. Select the `chrome-extension/` folder from this project
5. The 🛡️ shield icon will appear in your toolbar
6. Visit any webpage — suspicious links will be highlighted in red!

> **Note:** You'll need to create PNG icons (16x16, 48x48, 128x128) from the included SVG.  
> See `chrome-extension/icons/README.md` for instructions.

### Part 2: Running the Website
1. Navigate to the `website/` folder
2. Double-click `index.html` to open it in any browser (Chrome, Firefox, Edge, Safari)
3. Paste any URL or click an example to test it instantly

## How It Works

The detector uses a rule-based scoring system. When a URL is submitted, a JavaScript function parses it and runs it through a series of checks. Each failed check adds a specific amount of "risk points" to a total score. 

- **0-29 Points**: **SAFE** (Green) - The URL appears normal, though vigilance is always recommended.
- **30-59 Points**: **SUSPICIOUS** (Yellow) - The URL has unusual characteristics and should be treated with caution.
- **60-100 Points**: **DANGEROUS** (Red) - The URL exhibits multiple strong indicators of being malicious.

## Detection Checks

| Check | What it Detects | Max Risk Points |
| :--- | :--- | :---: |
| **Suspicious Keywords** | Words like `login`, `verify`, `secure`, `bank` in the URL. | 10 per word |
| **Unusual Protocol** | `data:` or `javascript:` URI schemes used to run malicious scripts. | 40 |
| **Punycode/Homograph** | `xn--` in domains, indicating possible foreign character deception. | 30 |
| **IP Address Usage** | Using an IP address instead of a domain name to obscure server identity. | 25 |
| **Suspicious TLDs** | Top-Level Domains known for abuse (e.g., `.xyz`, `.tk`, `.club`). | 20 |
| **Subdomain Count** | Excessive subdomains (e.g., `login.verify.account.paypal.com.evil.xyz`). | 20 |
| **Suspicious Characters** | The `@` symbol (which obscures the real domain) or excessive hyphens. | 20 |
| **URL Shorteners** | Services like `bit.ly` or `tinyurl` that hide the final destination. | 15 |
| **URL Length** | URLs longer than 75 characters, often used to hide the true domain. | 15 |
| **Connection Security** | Unencrypted `http://` instead of `https://`. | 10 |

## Educational Purpose Disclaimer

**IMPORTANT:** This tool is designed strictly for **educational purposes** to demonstrate how phishing detection heuristics work. It is NOT a production-grade security tool. Attackers constantly evolve their techniques, and a URL being marked as "Safe" by this tool does not guarantee that it is truly safe. Always exercise caution and use comprehensive security solutions for actual protection.

## Technologies Used

- **HTML5**: Semantic structure.
- **CSS3**: Styling, responsive design, animations (circular gauge).
- **JavaScript (ES6)**: URL parsing, regex evaluation, DOM manipulation.

## Future Improvements

- **Machine Learning Integration**: Replace rule-based heuristics with a trained classification model.
- **External API Integration**: Check URLs against live threat intelligence feeds (e.g., Google Safe Browsing API, VirusTotal).
- **Chrome Extension Version**: Port the tool into a browser extension that actively monitors visited URLs.
- **Real-time Database**: Log submitted malicious URLs for research and statistical analysis.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

*Placeholder*
