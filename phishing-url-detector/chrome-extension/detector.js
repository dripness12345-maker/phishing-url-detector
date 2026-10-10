/**
 * File: detector.js
 * Purpose: Contains the core logic for analyzing URLs and determining their risk level.
 * Author: Phishing URL Detector Project
 * 
 * Note: This file is shared between the content script (running on web pages)
 * and the popup script (running in the extension UI).
 */

/**
 * Analyzes a given URL for common phishing indicators.
 * @param {string} urlString - The URL to analyze
 * @returns {Object} - Result containing isSuspicious, riskScore, and reasons
 */
function analyzeURL(urlString) {
    // Initialize our result object
    const result = {
        isSuspicious: false,
        riskScore: 0,
        reasons: []
    };

    if (!urlString) {
        return result;
    }

    // Attempt to parse the URL. If it fails, it might be a relative path or invalid.
    let url;
    try {
        url = new URL(urlString);
    } catch (e) {
        // If it's not a valid URL (e.g., javascript:void(0) or a relative path),
        // we'll handle specific cases below using the raw string.
    }

    const lowerCaseUrl = urlString.toLowerCase();

    // 1. Check for data/javascript URI
    // Phishers often use data URIs or JS to obfuscate malicious content
    if (lowerCaseUrl.startsWith('data:') || lowerCaseUrl.startsWith('javascript:')) {
        result.riskScore += 60;
        result.reasons.push("Uses obfuscated data or javascript URI");
    }

    if (url) {
        // 2. Suspicious keywords in URL
        // These keywords are often used to create a false sense of urgency or legitimacy
        const suspiciousKeywords = [
            'login', 'signin', 'verify', 'account', 'secure', 'update', 'bank', 
            'paypal', 'confirm', 'password', 'credential', 'alert', 'suspend', 
            'restrict', 'unlock', 'authenticate', 'validate', 'billing', 'invoice', 
            'urgent', 'immediately', 'expire', 'ssn', 'social-security', 'ebay', 
            'apple', 'microsoft', 'netflix', 'amazon', 'wellsfargo'
        ];
        
        // Check if any keyword is present in the full URL
        const foundKeywords = suspiciousKeywords.filter(keyword => lowerCaseUrl.includes(keyword));
        if (foundKeywords.length > 0) {
            result.riskScore += 15 * foundKeywords.length;
            result.reasons.push(`Contains suspicious keywords: ${foundKeywords.join(', ')}`);
        }

        // 3. IP address as domain
        // Legitimate sites use domain names, not raw IP addresses
        const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
        if (ipRegex.test(url.hostname)) {
            result.riskScore += 40;
            result.reasons.push("Uses an IP address instead of a domain name");
        }

        // 4. Long URLs
        // Long URLs can be used to hide the true destination
        if (urlString.length > 75) {
            result.riskScore += 10;
            result.reasons.push("URL is unusually long (over 75 characters)");
        }

        // 5. Special characters
        // The '@' symbol makes the browser ignore everything before it (e.g., http://google.com@phishingsite.com)
        if (url.href.includes('@')) {
            result.riskScore += 50;
            result.reasons.push("Contains '@' symbol, which can hide the true destination");
        }
        
        // Excessive hyphens in domain are often used in spoofed domains (e.g., secure-login-update-account.com)
        const hyphenCount = (url.hostname.match(/-/g) || []).length;
        if (hyphenCount >= 3) {
            result.riskScore += 15;
            result.reasons.push("Domain contains an unusual amount of hyphens");
        }

        // 6. URL shorteners
        // Phishers use shorteners to hide malicious URLs
        const shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
            'is.gd', 'buff.ly', 'adf.ly', 'rb.gy'
        ];
        if (shorteners.some(shortener => url.hostname.includes(shortener))) {
            result.riskScore += 25;
            result.reasons.push("Uses a URL shortener service");
        }

        // 7. Too many subdomains
        // e.g., login.paypal.com.secure.update.phishingsite.com
        const dotCount = (url.hostname.match(/\./g) || []).length;
        if (dotCount > 3) {
            result.riskScore += 20;
            result.reasons.push("Contains too many subdomains");
        }

        // 8. Suspicious TLDs
        // Some Top Level Domains are cheap and frequently abused
        const suspiciousTLDs = [
            '.xyz', '.top', '.pw', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq', 
            '.buzz', '.club', '.work', '.date', '.racing', '.win', '.bid', 
            '.stream', '.download', '.click', '.link', '.info', '.site', 
            '.online', '.icu'
        ];
        if (suspiciousTLDs.some(tld => url.hostname.endsWith(tld))) {
            result.riskScore += 25;
            result.reasons.push("Uses a high-risk Top-Level Domain (TLD)");
        }

        // 9. No HTTPS
        // Modern secure sites almost always use HTTPS
        if (url.protocol === 'http:') {
            result.riskScore += 15;
            result.reasons.push("Does not use secure HTTPS protocol");
        }

        // 10. Homograph / punycode
        // 'xn--' indicates an internationalized domain, often used to create look-alike domains (e.g., apple.com vs аpple.com)
        if (url.hostname.includes('xn--')) {
            result.riskScore += 40;
            result.reasons.push("Uses Punycode (xn--), which may indicate a homograph attack");
        }
    }

    // Cap the score at 100
    if (result.riskScore > 100) {
        result.riskScore = 100;
    }

    // Determine if it's suspicious based on the threshold (30 points)
    if (result.riskScore >= 30) {
        result.isSuspicious = true;
    }

    return result;
}

// In case this is imported as a module in other environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { analyzeURL };
}
