/**
 * File: content.js
 * Purpose: Scans the current webpage for links, analyzes them using detector.js,
 *          highlights suspicious links, and displays a warning badge.
 * Author: Phishing URL Detector Project
 */

// We assume analyzeURL is available in the global scope because detector.js 
// is injected before content.js in manifest.json.

let suspiciousCount = 0;

/**
 * Scans all links on the page and applies warnings to suspicious ones.
 */
function scanLinks() {
    // Get all anchor (link) elements on the page
    const links = document.querySelectorAll('a');

    links.forEach(link => {
        const url = link.href;
        
        // Skip empty links or anchor links within the same page
        if (!url || url.startsWith('#')) return;

        // Analyze the URL using our shared detection logic
        const analysis = analyzeURL(url);

        if (analysis.isSuspicious) {
            suspiciousCount++;

            // Visual warning 1: Red dashed border
            link.style.border = '2px dashed red';
            link.style.backgroundColor = 'rgba(255, 0, 0, 0.1)';

            // Visual warning 2: Title attribute (shows on native hover)
            link.title = `⚠️ WARNING: Suspicious Link (Risk Score: ${analysis.riskScore}/100)\nReasons:\n- ${analysis.reasons.join('\n- ')}`;

            // Advanced visual warning: Tooltip styling can be injected via CSS if needed, 
            // but native title attribute handles hover decently.
        }
    });

    // Notify the background script about the findings
    chrome.runtime.sendMessage({ 
        type: 'SCAN_COMPLETE', 
        suspiciousCount: suspiciousCount 
    });

    // If we found suspicious links, show the floating badge
    if (suspiciousCount > 0) {
        createFloatingBadge();
    }
}

/**
 * Creates and injects a floating badge warning the user about suspicious links.
 */
function createFloatingBadge() {
    // Create the container
    const badge = document.createElement('div');
    badge.id = 'phishing-detector-badge';
    
    // Style the badge
    badge.style.position = 'fixed';
    badge.style.bottom = '20px';
    badge.style.right = '20px';
    badge.style.backgroundColor = '#dc3545'; // Danger red
    badge.style.color = '#ffffff';
    badge.style.padding = '12px 20px';
    badge.style.borderRadius = '8px';
    badge.style.boxShadow = '0 4px 6px rgba(0,0,0,0.3)';
    badge.style.zIndex = '999999';
    badge.style.fontFamily = 'Arial, sans-serif';
    badge.style.fontSize = '14px';
    badge.style.display = 'flex';
    badge.style.alignItems = 'center';
    badge.style.gap = '10px';

    // Badge content
    badge.innerHTML = `
        <span style="font-size: 18px;">⚠️</span>
        <strong>${suspiciousCount} suspicious link(s) found!</strong>
        <button id="phishing-badge-close" style="
            background: none;
            border: none;
            color: white;
            font-size: 16px;
            cursor: pointer;
            margin-left: 10px;
            padding: 0;
            line-height: 1;
        ">✕</button>
    `;

    // Add to body
    document.body.appendChild(badge);

    // Add close button functionality
    document.getElementById('phishing-badge-close').addEventListener('click', () => {
        badge.remove();
    });
}

// Run the scan once the page has loaded
window.addEventListener('load', scanLinks);
