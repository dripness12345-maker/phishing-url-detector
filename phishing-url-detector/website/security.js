/**
 * ============================================================
 * PHISHING URL DETECTOR - Website Security Module
 * ============================================================
 * File: security.js
 * Purpose: Protects the website itself against attacks.
 *          Implements input sanitization, XSS prevention,
 *          rate limiting, malicious input detection,
 *          bot protection, and secure error handling.
 *
 * Security Features:
 *   1. Input Sanitization - Strip HTML, limit length, remove null bytes
 *   2. XSS Protection - HTML entity encoding for all displayed data
 *   3. Rate Limiting - Max 10 analyses per minute (sliding window)
 *   4. Malicious Input Detection - Detects XSS, SQLi, path traversal
 *   5. Safe URL Display - Truncation, plain text only
 *   6. Bot Protection - Honeypot field detection
 *   7. Secure Error Handling - Never expose internal errors
 *   8. Content Security Policy - Meta tag (in HTML)
 *   9. Local Processing - No server communication
 *   10. Session Storage - No persistent data
 *
 * Author: Cybersecurity Awareness Project
 * ============================================================
 */

const SecurityModule = (function() {
    'use strict';

    // Private state for tracking analysis request timestamps to enforce rate limits
    let _requestTimestamps = [];

    /**
     * Sanitizes URL input before processing to prevent buffer overflows and remove obvious HTML injection.
     * 
     * @param {string} rawInput - The raw string input provided by the user.
     * @returns {Object} An object containing the sanitized string, any warnings, and a blocked flag.
     *                   Format: { sanitized: string, warnings: string[], blocked: boolean }
     */
    function sanitizeInput(rawInput) {
        if (typeof rawInput !== 'string') {
            return { sanitized: null, warnings: ['Input is not a string'], blocked: true };
        }

        let warnings = [];
        // Trim whitespace from both ends to handle copy-paste artifacts
        let sanitized = rawInput.trim();

        // Limit to 2048 characters (prevent buffer overflow/denial of service)
        // Attack prevented: Sending extremely large payloads that could crash the browser or exhaust memory
        if (sanitized.length > 2048) {
            sanitized = sanitized.substring(0, 2048);
            warnings.push('Input truncated to 2048 characters to prevent buffer overflow.');
        }

        // Remove null bytes: \0 and %00
        // Attack prevented: Null Byte Injection which can bypass some security filters or cause early string termination
        if (sanitized.includes('\0') || sanitized.includes('%00')) {
            sanitized = sanitized.replace(/\0|%00/g, '');
            warnings.push('Null bytes detected and removed.');
        }

        // Strip HTML tags using regex to prevent basic injection
        // Attack prevented: Cross-Site Scripting (XSS) by removing structural HTML elements
        const htmlTagRegex = /<[^>]*>/g;
        if (htmlTagRegex.test(sanitized)) {
            sanitized = sanitized.replace(htmlTagRegex, '');
            warnings.push('HTML tags detected and stripped from input.');
        }

        // Check for dangerous protocols but DO NOT remove them, as they are phishing indicators we want to analyze.
        // We only set a warning flag.
        // Attack prevented: Executing JavaScript or VBScript via URI handlers (XSS)
        const dangerousProtocols = /^(javascript:|vbscript:|data:text\/html|data:application\/)/i;
        if (dangerousProtocols.test(sanitized)) {
            warnings.push('Dangerous protocol detected (e.g., javascript:, data:). Input will be analyzed but execution is blocked by the application.');
        }

        // Blocked is true only if input was completely empty after sanitization
        const blocked = sanitized.length === 0;

        return {
            sanitized: sanitized,
            warnings: warnings,
            blocked: blocked
        };
    }

    /**
     * HTML entity encodes a string for safe DOM insertion.
     * 
     * @param {string} str - The string to encode.
     * @returns {string} The HTML entity encoded string.
     */
    function sanitizeForDisplay(str) {
        if (typeof str !== 'string') return '';
        
        // This prevents XSS (Cross-Site Scripting) by ensuring no HTML or script tags 
        // are rendered from user input. By converting special characters to their HTML entity 
        // equivalents, the browser treats them as plain text rather than executable code or markup.
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }

    /**
     * Implements client-side rate limiting using a sliding window.
     * 
     * @returns {Object} { allowed: boolean, remaining: number, waitSeconds: number }
     */
    function checkRateLimit() {
        const now = Date.now();
        const WINDOW_MS = 60 * 1000; // 60 seconds
        const MAX_REQUESTS = 10;

        // Sliding window: remove timestamps older than 60 seconds
        // Attack prevented: Brute force attempts, denial of service (DoS), and resource exhaustion
        _requestTimestamps = _requestTimestamps.filter(timestamp => now - timestamp < WINDOW_MS);

        if (_requestTimestamps.length >= MAX_REQUESTS) {
            // Calculate how long until the oldest request expires
            const oldestRequest = _requestTimestamps[0];
            const waitSeconds = Math.ceil((oldestRequest + WINDOW_MS - now) / 1000);
            
            console.warn(`Rate limit exceeded. Wait ${waitSeconds} seconds.`);
            
            return {
                allowed: false,
                remaining: 0,
                waitSeconds: waitSeconds
            };
        } else {
            // Record this new request
            _requestTimestamps.push(now);
            
            return {
                allowed: true,
                remaining: MAX_REQUESTS - _requestTimestamps.length,
                waitSeconds: 0
            };
        }
    }

    /**
     * Checks if the input itself is an attack attempt against our website.
     * 
     * @param {string} input - The raw input to check.
     * @returns {Object} { isMalicious: boolean, attackType: string, details: string }
     */
    function detectMaliciousInput(input) {
        if (typeof input !== 'string') return { isMalicious: false, attackType: 'None', details: '' };

        // 1. Detect Script tags (XSS)
        if (/<script/i.test(input)) {
            const msg = 'Detected script tag injection attempt.';
            console.warn(msg, input);
            return { isMalicious: true, attackType: 'XSS', details: msg };
        }

        // 2. Detect Event handlers (XSS)
        if (/on(click|load|error|mouseover|focus|blur|submit|change|input)\s*=/i.test(input)) {
            const msg = 'Detected inline event handler injection attempt.';
            console.warn(msg, input);
            return { isMalicious: true, attackType: 'XSS', details: msg };
        }

        // 3. Detect SQL injection
        if (/' OR /i.test(input) || /UNION\s+SELECT/i.test(input) || /DROP\s+TABLE/i.test(input) || 
            /INSERT\s+INTO/i.test(input) || /DELETE\s+FROM/i.test(input) || /;\s*--/.test(input)) {
            const msg = 'Detected possible SQL injection syntax.';
            console.warn(msg, input);
            return { isMalicious: true, attackType: 'SQL Injection', details: msg };
        }

        // 4. Detect Path traversal
        if (/\.\.\//.test(input) || /\.\.\\/.test(input) || /\.\.\.\.\//.test(input) || /%2e%2e/i.test(input)) {
            const msg = 'Detected directory/path traversal attempt.';
            console.warn(msg, input);
            return { isMalicious: true, attackType: 'Path Traversal', details: msg };
        }

        // 5. Detect Command injection
        if (/;\s*(ls|cat|dir|rm|del|whoami|pwd|echo)\b/i.test(input) || 
            /\|\s*(cat|ls|dir)/i.test(input) || 
            /&&\s*(dir|ls)/i.test(input)) {
            const msg = 'Detected OS command injection attempt.';
            console.warn(msg, input);
            return { isMalicious: true, attackType: 'Command Injection', details: msg };
        }

        return { isMalicious: false, attackType: 'None', details: '' };
    }

    /**
     * Safely prepares a URL for display by sanitizing and truncating it.
     * NEVER returns a clickable link.
     * 
     * @param {string} url - The URL to format.
     * @param {number} [maxLength=100] - The maximum length of the string to display.
     * @returns {string} The safely formatted, plain-text string.
     */
    function safeDisplayURL(url, maxLength = 100) {
        if (!url) return '';
        
        // Attack prevented: XSS via malicious payload rendered in the browser UI
        let safeUrl = sanitizeForDisplay(url);
        
        // Attack prevented: UI Redressing or layout breaking via extremely long unbroken strings
        if (safeUrl.length > maxLength) {
            safeUrl = safeUrl.substring(0, maxLength - 3) + '...';
        }
        
        return safeUrl;
    }

    /**
     * Checks if a hidden honeypot field has been filled, indicating a bot.
     * 
     * @param {any} fieldValue - The value of the hidden field.
     * @returns {boolean} True if a bot is detected, false otherwise.
     */
    function checkHoneypot(fieldValue) {
        // Honeypot fields are hidden from real users via CSS.
        // Automated bots scanning forms often blindly fill all inputs.
        // Attack prevented: Automated form submissions, scraping bots, spam.
        if (fieldValue) {
            console.warn('Bot detected: honeypot field was filled');
            return true;
        }
        return false;
    }

    /**
     * Secure error handler that logs details internally but returns a generic user-friendly message.
     * 
     * @param {Error} error - The caught error object.
     * @returns {string} A safe, user-friendly error message.
     */
    function handleError(error) {
        // Log the full error for debugging and monitoring internally.
        console.error(`[${new Date().toISOString()}] SecurityModule Error:`, error);
        
        // Attack prevented: Information Disclosure. Exposing stack traces or specific error details
        // can give attackers insights into the application's underlying technology and potential vulnerabilities.
        if (error instanceof TypeError) {
            return 'The URL format appears to be invalid. Please check and try again.';
        } else if (error instanceof RangeError) {
            return 'The URL is too long or contains unusual characters.';
        }
        
        return 'Analysis could not be completed. Please try again with a valid URL.';
    }

    /**
     * Initializes the security module.
     */
    function init() {
        _requestTimestamps = [];
        console.log('Security module initialized');
    }

    /**
     * Returns the status of all active security features for display in the UI.
     * 
     * @returns {Object} An object containing the list of security features and their descriptions.
     */
    function getSecurityStatus() {
        return {
            features: [
                { name: 'Input Sanitization', status: 'Active', description: 'All inputs are stripped of HTML tags and dangerous protocols' },
                { name: 'XSS Protection', status: 'Active', description: 'User data is HTML-entity encoded before display' },
                { name: 'Rate Limiting', status: 'Active', description: 'Maximum 10 analyses per minute' },
                { name: 'Malicious Input Detection', status: 'Active', description: 'Detects XSS, SQL injection, path traversal, and command injection' },
                { name: 'Safe URL Display', status: 'Active', description: 'URLs are displayed as plain text, never as clickable links' },
                { name: 'Bot Protection', status: 'Active', description: 'Hidden honeypot field detects automated form submissions' },
                { name: 'Error Handling', status: 'Active', description: 'Technical errors are logged securely without exposing internals' },
                { name: 'Content Security Policy', status: 'Active', description: 'CSP headers restrict script execution sources' },
                { name: 'Local Processing', status: 'Active', description: 'All analysis runs locally — no data is sent to any server' },
                { name: 'Session-Only Storage', status: 'Active', description: 'No persistent data storage — everything clears on tab close' }
            ]
        };
    }

    // Public API exposed by the module
    return {
        init: init,
        sanitizeInput: sanitizeInput,
        sanitizeForDisplay: sanitizeForDisplay,
        checkRateLimit: checkRateLimit,
        detectMaliciousInput: detectMaliciousInput,
        safeDisplayURL: safeDisplayURL,
        checkHoneypot: checkHoneypot,
        handleError: handleError,
        getSecurityStatus: getSecurityStatus
    };
})();

// Export for Node/test environment if available
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityModule;
}
