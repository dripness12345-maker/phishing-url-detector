/**
 * ============================================================
 * PHISHING URL DETECTOR - Advanced Detection Engine
 * ============================================================
 * File: detection.js
 * Purpose: Analyzes URLs for phishing indicators using 
 *          multiple detection modules and heuristic scoring.
 * 
 * Modules:
 *   1. Basic Checks (enhanced) - Keywords, IP, length, etc.
 *   2. Typosquatting Detection - Character substitution, 
 *      insertion, deletion, transposition
 *   3. Brand Impersonation - Subdomain abuse, keyword combos
 *   4. Advanced TLD Analysis - Tiered risk scoring
 *   5. URL Structure Analysis - Depth, paths, encoding
 *   6. Phishing Pattern Library - Known attack patterns
 *
 * Author: Cybersecurity Awareness Project
 * ============================================================
 */

// Helper function to calculate Levenshtein distance between two strings
// This calculates the minimum number of single-character edits (insertions, deletions, or substitutions)
// required to change one word into the other.
const levenshteinDistance = (a, b) => {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix = [];

    // Increment along the first column of each row
    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }

    // Increment each column in the first row
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }

    // Fill in the rest of the matrix
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1, // substitution
                    Math.min(
                        matrix[i][j - 1] + 1, // insertion
                        matrix[i - 1][j] + 1  // deletion
                    )
                );
            }
        }
    }

    return matrix[b.length][a.length];
};

// Helper function to extract the main registrable domain from a hostname
const extractMainDomain = (hostname) => {
    // Remove port if present
    hostname = hostname.split(':')[0];
    
    const parts = hostname.split('.');
    
    // If it's an IP or doesn't have a dot, return as is
    if (parts.length <= 1 || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        return hostname;
    }

    // Known multi-part TLDs (simplified list for this project)
    const multiPartTlds = ['co.uk', 'com.au', 'co.in', 'com.pk', 'co.jp', 'org.uk'];
    
    const possibleMultiTld = parts.slice(-2).join('.');
    
    if (multiPartTlds.includes(possibleMultiTld) && parts.length > 2) {
        return parts[parts.length - 3];
    }
    
    // Otherwise, return the second to last part (e.g., in www.google.com, returns google)
    return parts[parts.length - 2];
};

function performFullAnalysis(urlString) {
    // Initialize the result object
    let result = {
        riskScore: 0,
        riskLevel: 'SAFE',
        totalChecks: 0,
        checksPassed: 0,
        checksFailed: 0,
        checks: []
    };

    if (!urlString || typeof urlString !== 'string') {
        return result;
    }

    // Helper to add a check result
    const addCheck = (name, category, passed, points, finding, danger, example) => {
        result.totalChecks++;
        if (passed) {
            result.checksPassed++;
        } else {
            result.checksFailed++;
            result.riskScore += points;
        }
        
        result.checks.push({
            name,
            category,
            passed,
            points: passed ? 0 : points,
            finding,
            danger,
            example
        });
    };

    let urlObj;
    try {
        // If missing protocol, prepend http:// to parse correctly
        const parseableUrl = urlString.includes('://') ? urlString : 'http://' + urlString;
        urlObj = new URL(parseableUrl);
    } catch (e) {
        // Unparseable URL, we still do some basic string checks
        addCheck(
            'URL Parsing',
            'basic',
            false,
            20,
            'Invalid URL format',
            'Malicious links often use malformed structures to bypass simple filters',
            'http://[invalid-url'
        );
        // Default values to allow string-based checks to run safely
        urlObj = { hostname: urlString, pathname: urlString, protocol: 'http:', href: urlString };
    }

    const hostname = urlObj.hostname.toLowerCase();
    const pathname = urlObj.pathname.toLowerCase();
    const fullUrl = urlObj.href.toLowerCase();
    const mainDomain = extractMainDomain(hostname);

    // ==========================================
    // MODULE 1: BASIC CHECKS
    // ==========================================

    // 1. Suspicious Keywords
    const suspiciousKeywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'bank', 'paypal', 'confirm', 'password', 'credential', 'alert', 'suspend', 'restrict', 'unlock', 'authenticate', 'validate', 'billing', 'invoice', 'urgent', 'immediately', 'expire', 'ssn', 'social-security', 'ebay', 'apple', 'microsoft', 'netflix', 'amazon', 'wellsfargo'];
    const foundKeywords = suspiciousKeywords.filter(kw => fullUrl.includes(kw));
    if (foundKeywords.length > 0) {
        const points = foundKeywords.length * 10;
        addCheck(
            'Suspicious Keywords',
            'basic',
            false,
            points,
            `Found keywords: ${foundKeywords.join(', ')}`,
            'Phishing URLs use these words to create urgency or impersonate trusted brands',
            'http://paypal-login-verify.evil.com uses "paypal", "login", and "verify" to trick users'
        );
    } else {
        addCheck('Suspicious Keywords', 'basic', true, 0, 'No suspicious keywords found', 'Phishing URLs use these words to create urgency or impersonate trusted brands', 'http://paypal-login-verify.evil.com uses "paypal", "login", and "verify" to trick users');
    }

    // 2. IP Address as Domain
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
        addCheck('IP Address as Domain', 'basic', false, 30, 'Host is an IP address', 'Legitimate websites use domain names, not raw IP addresses. IPs hide the site identity.', 'http://192.168.1.1/login \u2014 you cannot verify who owns this IP');
    } else {
        addCheck('IP Address as Domain', 'basic', true, 0, 'Host uses a domain name', 'Legitimate websites use domain names, not raw IP addresses. IPs hide the site identity.', 'http://192.168.1.1/login \u2014 you cannot verify who owns this IP');
    }

    // 3. URL Length
    const urlLength = fullUrl.length;
    let lengthPoints = 0;
    if (urlLength > 250) lengthPoints = 30;
    else if (urlLength > 150) lengthPoints = 20;
    else if (urlLength > 75) lengthPoints = 10;
    
    if (lengthPoints > 0) {
        addCheck('URL Length', 'basic', false, lengthPoints, `URL is ${urlLength} characters long`, 'Extremely long URLs are used to hide the real destination in the address bar', 'http://www.legitimate-looking-site.com/very/long/path/to/hide/phishing/page');
    } else {
        addCheck('URL Length', 'basic', true, 0, `URL length is acceptable (${urlLength} chars)`, 'Extremely long URLs are used to hide the real destination in the address bar', 'http://www.legitimate-looking-site.com/very/long/path/to/hide/phishing/page');
    }

    // 4. Special Characters
    let hasAtSymbol = fullUrl.includes('@');
    let hyphenCount = (hostname.match(/-/g) || []).length;
    if (hasAtSymbol) {
        addCheck('Special Characters (@)', 'basic', false, 30, 'Contains @ symbol in URL', 'The @ symbol makes browsers ignore everything before it. http://google.com@evil.com actually goes to evil.com', 'http://www.google.com@malicious-site.com \u2014 this goes to malicious-site.com');
    } else {
        addCheck('Special Characters (@)', 'basic', true, 0, 'No @ symbol in URL', 'The @ symbol makes browsers ignore everything before it. http://google.com@evil.com actually goes to evil.com', 'http://www.google.com@malicious-site.com \u2014 this goes to malicious-site.com');
    }

    if (hyphenCount > 3) {
        addCheck('Excessive Hyphens', 'basic', false, 15, `Found ${hyphenCount} hyphens in domain`, 'Legitimate companies rarely use multiple hyphens in their domain names', 'http://www.secure-login-update-account.com');
    } else {
        addCheck('Excessive Hyphens', 'basic', true, 0, `Acceptable number of hyphens (${hyphenCount})`, 'Legitimate companies rarely use multiple hyphens in their domain names', 'http://www.secure-login-update-account.com');
    }

    // 5. URL Shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc'];
    if (shorteners.some(short => hostname.includes(short))) {
        addCheck('URL Shortener', 'basic', false, 30, 'URL shortener service detected', 'URL shorteners hide the real destination. Attackers use them to mask phishing links.', 'https://bit.ly/3xYz — you cannot see where this actually leads');
    } else {
        addCheck('URL Shortener', 'basic', true, 0, 'Not using a known URL shortener', 'URL shorteners hide the real destination. Attackers use them to mask phishing links.', 'https://bit.ly/3xYz — you cannot see where this actually leads');
    }

    // 6. Connection Security
    if (urlObj.protocol === 'http:') {
        addCheck('Connection Security', 'basic', false, 15, 'URL uses insecure HTTP protocol', 'HTTP sends data in plaintext. Any login page using HTTP can have credentials stolen in transit.', 'http://mybank-login.com \u2014 your password would be sent unencrypted');
    } else {
        addCheck('Connection Security', 'basic', true, 0, 'URL uses secure or other protocol', 'HTTP sends data in plaintext. Any login page using HTTP can have credentials stolen in transit.', 'http://mybank-login.com \u2014 your password would be sent unencrypted');
    }

    // 7. Punycode / Homograph
    if (hostname.includes('xn--')) {
        addCheck('Punycode / Homograph', 'basic', false, 35, 'Domain contains "xn--" indicating punycode', 'Punycode allows foreign characters that look identical to English letters. àpple.com looks like apple.com', 'xn--pple-43d.com displays as àpple.com \u2014 visually identical to apple.com');
    } else {
        addCheck('Punycode / Homograph', 'basic', true, 0, 'No punycode detected', 'Punycode allows foreign characters that look identical to English letters. àpple.com looks like apple.com', 'xn--pple-43d.com displays as àpple.com \u2014 visually identical to apple.com');
    }

    // 8. Protocol Scheme
    if (urlObj.protocol === 'data:' || urlObj.protocol === 'javascript:') {
        addCheck('Protocol Scheme', 'basic', false, 50, `Dangerous protocol detected: ${urlObj.protocol}`, 'Data and JavaScript URIs can execute malicious code directly in your browser without loading a webpage', 'javascript:alert(document.cookie) \u2014 can steal your session cookies');
    } else {
        addCheck('Protocol Scheme', 'basic', true, 0, 'Safe protocol used', 'Data and JavaScript URIs can execute malicious code directly in your browser without loading a webpage', 'javascript:alert(document.cookie) \u2014 can steal your session cookies');
    }

    // ==========================================
    // MODULE 2: TYPOSQUATTING
    // ==========================================
    
    // 9. Typosquatting Detection
    const brands = ['google', 'facebook', 'youtube', 'instagram', 'twitter', 'amazon', 'microsoft', 'apple', 'netflix', 'paypal', 'linkedin', 'whatsapp', 'telegram', 'tiktok', 'snapchat', 'yahoo', 'gmail', 'outlook', 'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'ebay', 'walmart', 'target', 'dropbox', 'github', 'stackoverflow', 'reddit', 'wikipedia'];
    
    let isTyposquat = false;
    let typosquatMethod = [];
    let matchedBrand = '';
    
    // a) Character substitution normalization
    const normalizedDomain = mainDomain
        .replace(/0/g, 'o')
        .replace(/1/g, 'i') // simplified, 'l' is also common but context dependent
        .replace(/3/g, 'e')
        .replace(/@/g, 'a')
        .replace(/5/g, 's')
        .replace(/9/g, 'g');

    for (const brand of brands) {
        if (mainDomain === brand) continue; // It's exactly the brand (could be legit or just using the name, not a typosquat)
        
        let localTyposquat = false;
        
        // a) substitution match
        if (normalizedDomain === brand) {
            localTyposquat = true;
            typosquatMethod.push('Character substitution');
        }
        
        // b) Levenshtein distance
        const dist = levenshteinDistance(mainDomain, brand);
        if (dist === 1 || dist === 2) {
            localTyposquat = true;
            typosquatMethod.push('Edit distance (Levenshtein)');
        }
        
        // c) Hyphen tricks
        const deHyphenated = mainDomain.replace(/-/g, '');
        if (deHyphenated === brand || deHyphenated.includes(brand)) {
            localTyposquat = true;
            typosquatMethod.push('Hyphen insertion');
        }
        
        // d) Subdomain tricks
        const subdomains = hostname.replace(`.${mainDomain}`, '').split('.');
        if (subdomains.includes(brand) && mainDomain !== brand) {
            isTyposquat = true;
            matchedBrand = brand;
            typosquatMethod.push('Brand in subdomain');
            break; // Stop on first strong subdomain match
        }

        if (localTyposquat) {
            isTyposquat = true;
            matchedBrand = brand;
            break;
        }
    }

    if (isTyposquat) {
        let points = 25;
        if (typosquatMethod.includes('Brand in subdomain')) {
            points = 30;
        } else if (typosquatMethod.length > 1) {
            points = 35;
        }
        
        addCheck(
            'Typosquatting Detection',
            'typosquatting',
            false,
            points,
            `Detected impersonation of "${matchedBrand}" via: ${typosquatMethod.join(', ')}`,
            'Attackers register domains visually similar to popular brands to trick users who misspell URLs',
            'g00gle.com instead of google.com'
        );
    } else {
        addCheck('Typosquatting Detection', 'typosquatting', true, 0, 'No typosquatting detected', 'Attackers register domains visually similar to popular brands to trick users who misspell URLs', 'g00gle.com instead of google.com');
    }

    // ==========================================
    // MODULE 3: BRAND IMPERSONATION
    // ==========================================

    // 10. Brand Impersonation
    let brandPoints = 0;
    let brandFindings = [];
    
    const subdomainsArr = hostname.replace(new RegExp(`\\.?${mainDomain}(\\.[a-z]+)*$`, 'i'), '').split('.').filter(Boolean);
    const hasBrandInSubdomain = brands.some(b => subdomainsArr.includes(b) && mainDomain !== b);
    
    if (hasBrandInSubdomain) {
        brandPoints += 30;
        brandFindings.push('Brand name in subdomain');
    }

    const actionWords = ['secure', 'login', 'verify', 'account', 'update', 'confirm', 'support', 'help', 'official', 'authentic'];
    const financialWords = ['bank', 'pay', 'money', 'transfer', 'wallet', 'card', 'credit'];
    
    const urlContainsBrand = brands.some(b => fullUrl.includes(b) && mainDomain !== b);
    const urlContainsAction = actionWords.some(w => fullUrl.includes(w));
    const urlContainsFinance = financialWords.some(w => fullUrl.includes(w));
    
    if (urlContainsBrand && urlContainsAction) {
        brandPoints += 25;
        brandFindings.push('Brand name combined with action words');
    }
    
    if (urlContainsBrand && urlContainsFinance) {
        brandPoints += 35;
        brandFindings.push('Brand name combined with financial words');
    }

    const brandsInUrl = brands.filter(b => fullUrl.includes(b));
    if (brandsInUrl.length > 1) {
        brandPoints += 20;
        brandFindings.push(`Multiple brands in URL: ${brandsInUrl.join(', ')}`);
    }

    if (brandPoints > 0) {
        addCheck(
            'Brand Impersonation',
            'brand',
            false,
            Math.min(brandPoints, 80), // Cap just in case
            brandFindings.join('; '),
            'Attackers blatantly use brand names combined with urgent keywords to impersonate official communications',
            'paypal.evil-login.xyz or paypal-secure-update.com'
        );
    } else {
        addCheck('Brand Impersonation', 'brand', true, 0, 'No explicit brand impersonation detected', 'Attackers blatantly use brand names combined with urgent keywords to impersonate official communications', 'paypal.evil-login.xyz or paypal-secure-update.com');
    }

    // ==========================================
    // MODULE 4: ADVANCED TLD ANALYSIS
    // ==========================================
    
    // 11. Advanced TLD Analysis
    const tldMatch = hostname.match(/\.([a-z0-9\-]+)$/i);
    const tld = tldMatch ? `.${tldMatch[1].toLowerCase()}` : '';
    
    const criticalTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
    const highTLDs = ['.xyz', '.top', '.club', '.online', '.site', '.website', '.space', '.fun', '.icu', '.pw', '.cc', '.su'];
    const mediumTLDs = ['.info', '.biz', '.mobi', '.name', '.pro', '.tel', '.link', '.click', '.download', '.zip', '.review', '.country', '.kim', '.science', '.work'];
    const lowTLDs = ['.io', '.co', '.me', '.us', '.tv', '.fm'];
    const safeTLDs = ['.gov', '.edu', '.mil'];
    const trustedTLDs = ['.com', '.org', '.net', '.uk', '.de', '.fr', '.jp', '.au', '.ca', '.in', '.pk'];

    let tldPoints = 0;
    let tldFinding = `Domain uses TLD ${tld}`;
    let isSuspiciousTld = false; // Used in pattern checks

    if (criticalTLDs.includes(tld)) {
        tldPoints = 40;
        isSuspiciousTld = true;
        addCheck('Advanced TLD Analysis', 'tld', false, tldPoints, `${tldFinding} (CRITICAL RISK)`, 'These TLDs are often free or heavily abused by attackers due to lack of regulation.', 'evil-site.tk');
    } else if (highTLDs.includes(tld)) {
        tldPoints = 30;
        isSuspiciousTld = true;
        addCheck('Advanced TLD Analysis', 'tld', false, tldPoints, `${tldFinding} (HIGH RISK)`, 'These cheap TLDs have a disproportionately high rate of malicious registrations.', 'secure-login.xyz');
    } else if (mediumTLDs.includes(tld)) {
        tldPoints = 15;
        isSuspiciousTld = true;
        addCheck('Advanced TLD Analysis', 'tld', false, tldPoints, `${tldFinding} (MEDIUM RISK)`, 'These TLDs are moderately abused or commonly used for spam.', 'update-account.click');
    } else if (lowTLDs.includes(tld)) {
        tldPoints = 5;
        addCheck('Advanced TLD Analysis', 'tld', false, tldPoints, `${tldFinding} (LOW RISK)`, 'These TLDs are generally acceptable but occasionally used by attackers.', 'app.io');
    } else if (safeTLDs.includes(tld)) {
        result.riskScore = Math.max(0, result.riskScore - 10);
        addCheck('Advanced TLD Analysis', 'tld', true, 0, `${tldFinding} (SAFE)`, 'These TLDs are heavily restricted and verified (e.g., government or education).', 'whitehouse.gov');
    } else if (trustedTLDs.includes(tld)) {
        addCheck('Advanced TLD Analysis', 'tld', true, 0, `${tldFinding} (TRUSTED)`, 'These are standard TLDs, though still can be compromised or used by attackers.', 'google.com');
    } else {
        // Unknown or other TLD
        addCheck('Advanced TLD Analysis', 'tld', true, 0, `${tldFinding} (UNKNOWN/NEUTRAL)`, 'Standard TLD evaluation.', 'example.com');
    }

    // ==========================================
    // MODULE 5: URL STRUCTURE ANALYSIS
    // ==========================================

    // 12. Subdomain Depth
    const subdomainCount = hostname.split('.').length - 2; // subtracting main domain and TLD roughly
    if (subdomainCount >= 4) {
        addCheck('Subdomain Depth', 'structure', false, 35, `Found ${subdomainCount} subdomains`, 'Excessive subdomains are used to push the real domain out of view in the address bar', 'secure.login.paypal.com.evil-site.xyz \u2014 the real domain is evil-site.xyz');
    } else if (subdomainCount === 3) {
        addCheck('Subdomain Depth', 'structure', false, 20, 'Found 3 subdomains', 'Excessive subdomains are used to push the real domain out of view in the address bar', 'secure.login.paypal.com.evil-site.xyz \u2014 the real domain is evil-site.xyz');
    } else if (subdomainCount === 2) {
        addCheck('Subdomain Depth', 'structure', false, 10, 'Found 2 subdomains', 'Excessive subdomains are used to push the real domain out of view in the address bar', 'secure.login.paypal.com.evil-site.xyz \u2014 the real domain is evil-site.xyz');
    } else {
        addCheck('Subdomain Depth', 'structure', true, 0, 'Normal subdomain depth', 'Excessive subdomains are used to push the real domain out of view in the address bar', 'secure.login.paypal.com.evil-site.xyz \u2014 the real domain is evil-site.xyz');
    }

    // 13. URL Path Depth
    const pathSegments = pathname.split('/').filter(Boolean);
    const depth = pathSegments.length;
    if (depth >= 8) {
        addCheck('URL Path Depth', 'structure', false, 30, `Deep path found (${depth} segments)`, 'Deep URL paths can indicate hidden phishing pages buried in compromised websites', '/wp-content/themes/twentyseventeen/assets/css/login/auth/');
    } else if (depth >= 6) {
        addCheck('URL Path Depth', 'structure', false, 20, `Deep path found (${depth} segments)`, 'Deep URL paths can indicate hidden phishing pages buried in compromised websites', '/wp-content/themes/twentyseventeen/assets/css/login/auth/');
    } else if (depth >= 4) {
        addCheck('URL Path Depth', 'structure', false, 10, `Moderate path depth (${depth} segments)`, 'Deep URL paths can indicate hidden phishing pages buried in compromised websites', '/wp-content/themes/twentyseventeen/assets/css/login/auth/');
    } else {
        addCheck('URL Path Depth', 'structure', true, 0, 'Normal path depth', 'Deep URL paths can indicate hidden phishing pages buried in compromised websites', '/wp-content/themes/twentyseventeen/assets/css/login/auth/');
    }

    // 14. Path Keywords
    const pathSusKeywords = ['login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'validate', 'account', 'accounts', 'myaccount', 'update', 'updateinfo', 'updateaccount', 'confirm', 'confirmation', 'secure', 'security', 'secured', 'banking', 'online-banking', 'password', 'passwd', 'pwd', 'credential', 'credentials', 'recover', 'recovery', 'restore', 'suspend', 'suspended', 'limited', 'unlock', 'unblock', 'reactivate', 'billing', 'payment', 'checkout', 'invoice', 'receipt', 'transaction'];
    const foundPathKws = pathSusKeywords.filter(kw => pathname.includes(kw));
    if (foundPathKws.length > 0) {
        const pPts = Math.min(foundPathKws.length * 10, 30);
        addCheck('Path Keywords', 'structure', false, pPts, `Found suspicious keywords in path: ${foundPathKws.join(', ')}`, 'Suspicious keywords in URL paths indicate pages designed to steal credentials', '/secure/login/verify.php');
    } else {
        addCheck('Path Keywords', 'structure', true, 0, 'No suspicious keywords in path', 'Suspicious keywords in URL paths indicate pages designed to steal credentials', '/secure/login/verify.php');
    }

    // 15. Numbers in Domain
    const domainNumbers = mainDomain.replace(/[^0-9]/g, '').length;
    if (domainNumbers >= 3) {
        addCheck('Numbers in Domain', 'structure', false, 15, `Found ${domainNumbers} numbers in domain name`, 'Legitimate brands rarely include numbers in their domain names', 'paypa1-secure55.com \u2014 numbers used to impersonate "paypal"');
    } else if (domainNumbers >= 1) {
        addCheck('Numbers in Domain', 'structure', false, 5, `Found ${domainNumbers} numbers in domain name`, 'Legitimate brands rarely include numbers in their domain names', 'paypa1-secure55.com \u2014 numbers used to impersonate "paypal"');
    } else {
        addCheck('Numbers in Domain', 'structure', true, 0, 'No numbers in domain name', 'Legitimate brands rarely include numbers in their domain names', 'paypa1-secure55.com \u2014 numbers used to impersonate "paypal"');
    }

    // 16. Domain Length
    const domainLen = hostname.length;
    if (domainLen >= 30) {
        addCheck('Domain Length', 'structure', false, 25, `Domain length is ${domainLen} characters`, 'Very long domain names are uncommon for legitimate businesses and may indicate phishing', 'this-is-a-very-long-domain-name-to-hide-phishing.com');
    } else if (domainLen >= 21) {
        addCheck('Domain Length', 'structure', false, 15, `Domain length is ${domainLen} characters`, 'Very long domain names are uncommon for legitimate businesses and may indicate phishing', 'this-is-a-very-long-domain-name-to-hide-phishing.com');
    } else if (domainLen >= 11) {
        addCheck('Domain Length', 'structure', false, 5, `Domain length is ${domainLen} characters`, 'Very long domain names are uncommon for legitimate businesses and may indicate phishing', 'this-is-a-very-long-domain-name-to-hide-phishing.com');
    } else {
        addCheck('Domain Length', 'structure', true, 0, `Domain length is short (${domainLen} chars)`, 'Very long domain names are uncommon for legitimate businesses and may indicate phishing', 'this-is-a-very-long-domain-name-to-hide-phishing.com');
    }

    // 17. Redirect Indicators
    const redirectParams = ['redirect=', 'url=', 'link=', 'goto=', 'return=', 'returnurl=', 'next=', 'forward=', 'redir=', 'destination='];
    if (redirectParams.some(param => fullUrl.includes(param))) {
        addCheck('Redirect Indicators', 'structure', false, 30, 'URL contains potential redirect parameters', 'Redirect parameters can send you to a phishing page after interacting with a seemingly legitimate site', 'legitimate-site.com/login?redirect=http://evil.com \u2014 redirects you after login');
    } else {
        addCheck('Redirect Indicators', 'structure', true, 0, 'No redirect indicators found', 'Redirect parameters can send you to a phishing page after interacting with a seemingly legitimate site', 'legitimate-site.com/login?redirect=http://evil.com \u2014 redirects you after login');
    }

    // 18. URL Encoding Tricks
    const encodedCount = (fullUrl.match(/%[0-9A-Fa-f]{2}/g) || []).length;
    if (encodedCount > 5) {
        addCheck('URL Encoding Tricks', 'structure', false, 20, `Found ${encodedCount} percent-encoded characters`, 'Excessive URL encoding hides the true URL content from casual inspection', 'http://site.com/%6c%6f%67%69%6e');
    } else {
        addCheck('URL Encoding Tricks', 'structure', true, 0, 'Normal level of URL encoding', 'Excessive URL encoding hides the true URL content from casual inspection', 'http://site.com/%6c%6f%67%69%6e');
    }

    // ==========================================
    // MODULE 6: PHISHING PATTERNS
    // ==========================================

    // 19. Fake Login Page Pattern
    const hasBrand = brands.some(b => fullUrl.includes(b));
    const isOfficialDomain = brands.some(b => mainDomain === b);
    const hasLoginWord = fullUrl.includes('login') || fullUrl.includes('signin');
    
    if (hasBrand && hasLoginWord && !isOfficialDomain) {
        addCheck('Fake Login Page Pattern', 'pattern', false, 40, 'Mimics login page for a brand but hosted elsewhere', 'This URL mimics a login page for a known brand but is hosted on a different domain', 'paypal.com-login-secure.xyz');
    } else {
        addCheck('Fake Login Page Pattern', 'pattern', true, 0, 'Does not match fake login pattern', 'This URL mimics a login page for a known brand but is hosted on a different domain', 'paypal.com-login-secure.xyz');
    }

    // 20. Account Verification Scam
    const hasVerify = fullUrl.includes('verify') || fullUrl.includes('confirm');
    const hasAccount = fullUrl.includes('account') || fullUrl.includes('email');
    const isShortener = shorteners.some(short => hostname.includes(short));
    
    if (hasVerify && hasAccount && (isSuspiciousTld || isShortener)) {
        addCheck('Account Verification Scam', 'pattern', false, 35, 'Matches account verification scam pattern', 'Fake verification pages trick users into "confirming" their credentials on attacker-controlled sites', 'verify-email-account.tk');
    } else {
        addCheck('Account Verification Scam', 'pattern', true, 0, 'Does not match verification scam pattern', 'Fake verification pages trick users into "confirming" their credentials on attacker-controlled sites', 'verify-email-account.tk');
    }

    // 21. Prize/Lottery Scam
    const prizeKeywords = ['winner', 'won', 'prize', 'lottery', 'reward', 'gift', 'free', 'congratulations', 'selected', 'chosen'];
    if (prizeKeywords.some(kw => fullUrl.includes(kw))) {
        addCheck('Prize/Lottery Scam', 'pattern', false, 30, 'Contains prize/lottery related keywords', 'Prize and lottery scams lure victims with fake winnings to steal personal information', 'you-are-the-winner.free-prize.xyz \u2014 classic lottery scam URL');
    } else {
        addCheck('Prize/Lottery Scam', 'pattern', true, 0, 'No prize/lottery keywords found', 'Prize and lottery scams lure victims with fake winnings to steal personal information', 'you-are-the-winner.free-prize.xyz \u2014 classic lottery scam URL');
    }

    // 22. Urgency Scam
    const urgencyKeywords = ['urgent', 'immediately', 'asap', 'expire', 'expires', 'expiring', 'limited-time', 'act-now', 'last-chance'];
    if (urgencyKeywords.some(kw => fullUrl.includes(kw))) {
        addCheck('Urgency Scam', 'pattern', false, 20, 'Contains urgency keywords', 'Urgency words pressure victims into acting without thinking, a classic social engineering tactic', 'act-now-account-expires.com');
    } else {
        addCheck('Urgency Scam', 'pattern', true, 0, 'No urgency keywords found', 'Urgency words pressure victims into acting without thinking, a classic social engineering tactic', 'act-now-account-expires.com');
    }

    // 23. Tech Support Scam
    const techKeywords = ['virus', 'infected', 'malware', 'hacked', 'compromised', 'at-risk', 'warning', 'alert', 'error', 'support', 'helpdesk'];
    if (techKeywords.some(kw => fullUrl.includes(kw))) {
        addCheck('Tech Support Scam', 'pattern', false, 20, 'Contains tech support scare keywords', 'Fake tech support pages scare users into calling fraudulent support numbers or installing malware', 'warning-virus-infected-pc.com');
    } else {
        addCheck('Tech Support Scam', 'pattern', true, 0, 'No tech support scare keywords', 'Fake tech support pages scare users into calling fraudulent support numbers or installing malware', 'warning-virus-infected-pc.com');
    }

    // 24. Financial Scam
    const financeScamKeywords = ['refund', 'cashback', 'bonus', 'claim', 'irs', 'tax', 'government'];
    if (financeScamKeywords.some(kw => fullUrl.includes(kw))) {
        if (isSuspiciousTld) {
            addCheck('Financial Scam', 'pattern', false, 30, 'Contains financial scam keywords on suspicious TLD', 'Financial scam URLs promise money to trick victims into providing bank details', 'irs-tax-refund-claim.xyz');
        } else {
            addCheck('Financial Scam', 'pattern', false, 15, 'Contains financial scam keywords', 'Financial scam URLs promise money to trick victims into providing bank details', 'irs-tax-refund-claim.xyz');
        }
    } else {
        addCheck('Financial Scam', 'pattern', true, 0, 'No financial scam keywords found', 'Financial scam URLs promise money to trick victims into providing bank details', 'irs-tax-refund-claim.xyz');
    }

    // ==========================================
    // FINAL SCORING AND LEVEL CALCULATION
    // ==========================================

    // Ensure score is within bounds
    result.riskScore = Math.max(0, Math.min(100, result.riskScore));

    // Determine risk level based on score
    if (result.riskScore <= 20) {
        result.riskLevel = 'SAFE';
    } else if (result.riskScore <= 40) {
        result.riskLevel = 'LOW RISK';
    } else if (result.riskScore <= 60) {
        result.riskLevel = 'SUSPICIOUS';
    } else if (result.riskScore <= 80) {
        result.riskLevel = 'HIGH RISK';
    } else {
        result.riskLevel = 'CRITICAL';
    }

    return result;
}

// Export for module usage (CommonJS or ES6 depending on env) if needed,
// but as requested, this is declared at the top level as a global function.
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { performFullAnalysis, levenshteinDistance, extractMainDomain };
}
