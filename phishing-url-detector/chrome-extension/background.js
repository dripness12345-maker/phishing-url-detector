/**
 * File: background.js
 * Purpose: Service worker that runs in the background. It listens for messages 
 *          from content scripts and updates the extension icon badge.
 * Author: Phishing URL Detector Project
 */

// Listen for messages from our content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Check if the message is reporting a completed scan
    if (message.type === 'SCAN_COMPLETE') {
        const tabId = sender.tab.id;
        const count = message.suspiciousCount;

        if (count > 0) {
            // Show the number of suspicious links on the extension badge
            chrome.action.setBadgeText({ text: count.toString(), tabId: tabId });
            // Set badge background to red for danger
            chrome.action.setBadgeBackgroundColor({ color: '#dc3545', tabId: tabId });
        } else {
            // If safe, we could optionally show a green checkmark or nothing
            chrome.action.setBadgeText({ text: 'SAFE', tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: '#28a745', tabId: tabId });
        }
    }
});
