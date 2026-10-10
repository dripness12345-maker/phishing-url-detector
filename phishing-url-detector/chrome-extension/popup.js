/**
 * File: popup.js
 * Purpose: Handles the user interface logic for the extension popup.
 * Author: Phishing URL Detector Project
 */

document.addEventListener('DOMContentLoaded', () => {
    // Elements
    const urlInput = document.getElementById('url-input');
    const checkBtn = document.getElementById('check-btn');
    const resultsArea = document.getElementById('results-area');
    const scoreText = document.getElementById('score-text');
    const progressBarFill = document.getElementById('progress-bar-fill');
    const verdict = document.getElementById('verdict');
    const reasonsList = document.getElementById('reasons-list');
    const pageStatus = document.getElementById('page-status');

    // 1. Get status of current page by asking the content script
    // Note: We need to get the active tab and then communicate with its content script
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const currentTab = tabs[0];
        
        if (currentTab && currentTab.url) {
            // We can also run a quick check on the page URL itself
            const pageAnalysis = analyzeURL(currentTab.url);
            
            // Or get the count from badge text (simplest way to check state set by background script)
            chrome.action.getBadgeText({ tabId: currentTab.id }, (badgeText) => {
                if (badgeText && badgeText !== 'SAFE' && parseInt(badgeText) > 0) {
                    pageStatus.textContent = `⚠️ ${badgeText} suspicious links detected`;
                    pageStatus.style.backgroundColor = 'var(--danger)';
                    pageStatus.style.color = '#fff';
                } else if (pageAnalysis.isSuspicious) {
                    pageStatus.textContent = '⚠️ This page URL is suspicious!';
                    pageStatus.style.backgroundColor = 'var(--danger)';
                    pageStatus.style.color = '#fff';
                } else {
                    pageStatus.textContent = '✅ Page looks safe';
                    pageStatus.style.backgroundColor = 'var(--safe)';
                    pageStatus.style.color = '#000';
                }
            });
        }
    });

    // 2. Handle manual URL check
    checkBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Please enter a URL to check.');
            return;
        }

        // Run the detection logic (analyzeURL is available from detector.js)
        const analysis = analyzeURL(url);
        
        // Display results
        showResults(analysis);
    });

    // Allow pressing Enter in input field
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            checkBtn.click();
        }
    });

    /**
     * Updates the UI to show the analysis results
     * @param {Object} analysis - The result from analyzeURL()
     */
    function showResults(analysis) {
        // Show the hidden results area
        resultsArea.classList.remove('hidden');

        // Update score
        scoreText.textContent = `${analysis.riskScore}/100`;
        progressBarFill.style.width = `${analysis.riskScore}%`;

        // Determine color class based on score
        let colorClass = 'safe';
        let verdictText = 'Looks Safe!';
        
        if (analysis.riskScore >= 60) {
            colorClass = 'danger';
            verdictText = '🚨 Highly Suspicious!';
        } else if (analysis.riskScore >= 30) {
            colorClass = 'warning';
            verdictText = '⚠️ Potentially Unsafe';
        }

        // Apply classes and text
        progressBarFill.className = `progress-bar-fill ${colorClass}`;
        verdict.className = `verdict ${colorClass}`;
        verdict.textContent = verdictText;

        // Clear and populate reasons list
        reasonsList.innerHTML = '';
        
        if (analysis.reasons.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No obvious threats detected.';
            reasonsList.appendChild(li);
        } else {
            analysis.reasons.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = reason;
                reasonsList.appendChild(li);
            });
        }
    }
});
