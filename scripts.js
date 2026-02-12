// ============================================================================
// PHISHGUARD v2.0 - COMPLETE FRONTEND (FIXED)
// - Button blocking (REQUIREMENT #2)
// - URL validation
// - Proper error handling
// - All original features preserved
// ============================================================================

"use strict";

// ============================================================================
// GLOBAL STATE MANAGEMENT
// ============================================================================

const PhishGuard = {
    // Application state
    state: {
        currentTab: 'scanner',
        lastAnalysis: null,
        isAnalyzing: false,  // FIXED: Track analyzing state
        statsData: null,
        historyData: []
    },
    
    // Quiz state
    quiz: {
        questions: [],
        currentIndex: 0,
        userAnswers: [],
        score: 0
    },
    
    // Configuration
    config: {
        API_BASE: window.location.origin,
        CACHE_DURATION: 300000, // 5 minutes
        MAX_BATCH_URLS: 10,
        HISTORY_PAGE_SIZE: 20
    }
};

// ============================================================================
// QUIZ DATABASE
// ============================================================================

const QUIZ_QUESTIONS = [
    {
        question: "What is the most common sign of a phishing email?",
        options: [
            "Urgent action required",
            "Personalized greeting",
            "Official domain",
            "No links"
        ],
        answer: "Urgent action required"
    },
    {
        question: "Which of these URLs is suspicious?",
        options: [
            "paypal.com",
            "paypal-secure-login.com",
            "paypal.co.uk",
            "help.paypal.com"
        ],
        answer: "paypal-secure-login.com"
    },
    {
        question: "What does HTTPS ensure on a website?",
        options: [
            "The site is legitimate",
            "The connection is encrypted",
            "The site has no viruses",
            "Google Verified"
        ],
        answer: "The connection is encrypted"
    },
    {
        question: "How should you verify a suspicious link?",
        options: [
            "Click it immediately",
            "Hover over it to see the URL",
            "Forward it to a friend",
            "Ignore it"
        ],
        answer: "Hover over it to see the URL"
    },
    {
        question: "What is Two-Factor Authentication (2FA)?",
        options: [
            "Using two passwords",
            "A second security layer (like SMS code)",
            "Double encryption",
            "Two firewalls"
        ],
        answer: "A second security layer (like SMS code)"
    },
    {
        question: "What is a homograph attack?",
        options: [
            "Using similar-looking characters to mimic domains",
            "Attacking home networks",
            "Grammar mistakes in emails",
            "Graph-based visualization"
        ],
        answer: "Using similar-looking characters to mimic domains"
    },
    {
        question: "Why is a newly registered domain suspicious?",
        options: [
            "It's always malicious",
            "Attackers often use new domains to avoid detection",
            "New domains are slower",
            "They can't have SSL"
        ],
        answer: "Attackers often use new domains to avoid detection"
    },
    {
        question: "What does a self-signed SSL certificate indicate?",
        options: [
            "Maximum security",
            "Not verified by a trusted authority",
            "Google approved",
            "Bank-grade encryption"
        ],
        answer: "Not verified by a trusted authority"
    },
    {
        question: "What should you do if you receive a suspicious email?",
        options: [
            "Click all links to investigate",
            "Reply asking if it's legitimate",
            "Report it as spam and delete",
            "Forward to all contacts as warning"
        ],
        answer: "Report it as spam and delete"
    },
    {
        question: "Which domain extension is commonly abused by phishers?",
        options: [
            ".com",
            ".org",
            ".tk",
            ".edu"
        ],
        answer: ".tk"
    }
];

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 PhishGuard v2.0 Initializing...');
    
    // Initialize all components
    initializeEventListeners();
    initializeQuiz();
    loadDashboardData();
    
    console.log('✅ PhishGuard Ready!');
});

/**
 * Initialize all event listeners
 */
function initializeEventListeners() {
    // URL Input - Enter key support
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !PhishGuard.state.isAnalyzing) {
                e.preventDefault();
                analyzeURL();
            }
        });
    }
    
    // History search - Enter key support
    const historySearch = document.getElementById('historySearch');
    if (historySearch) {
        historySearch.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                searchHistory();
            }
        });
        
        // Real-time search (debounced)
        let searchTimeout;
        historySearch.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                if (this.value.trim()) {
                    searchHistory();
                } else {
                    loadHistory();
                }
            }, 500);
        });
    }
    
    // Batch analysis
    const batchBtn = document.getElementById('analyzeBatchBtn');
    if (batchBtn) {
        batchBtn.addEventListener('click', analyzeBatch);
    }
}

/**
 * Load dashboard statistics and history
 */
async function loadDashboardData() {
    await Promise.all([
        loadStatistics(),
        loadHistory()
    ]);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Show notification to user
 */
function showNotification(message, type = 'info') {
    const colors = {
        error: '#dc2626',
        success: '#16a34a',
        info: '#2563eb',
        warning: '#d97706'
    };
    
    const icons = {
        error: 'fa-exclamation-circle',
        success: 'fa-check-circle',
        info: 'fa-info-circle',
        warning: 'fa-exclamation-triangle'
    };
    
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 16px 20px;
        background: ${colors[type] || colors.info};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
        word-wrap: break-word;
        display: flex;
        align-items: center;
        gap: 12px;
        font-weight: 500;
    `;
    
    notification.innerHTML = `
        <i class="fas ${icons[type] || icons.info}" style="font-size: 1.2rem;"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

/**
 * Get theme colors based on risk level
 */
function getTheme(level) {
    const themes = {
        'CRITICAL': {
            color: '#dc2626',
            icon: 'fa-ban',
            bg: '#fef2f2',
            gradient: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)'
        },
        'HIGH': {
            color: '#ea580c',
            icon: 'fa-exclamation-triangle',
            bg: '#fff7ed',
            gradient: 'linear-gradient(135deg, #ea580c 0%, #c2410c 100%)'
        },
        'MEDIUM': {
            color: '#f59e0b',
            icon: 'fa-exclamation-circle',
            bg: '#fffbeb',
            gradient: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)'
        },
        'LOW': {
            color: '#84cc16',
            icon: 'fa-check-circle',
            bg: '#f7fee7',
            gradient: 'linear-gradient(135deg, #84cc16 0%, #65a30d 100%)'
        },
        'SAFE': {
            color: '#10b981',
            icon: 'fa-shield-alt',
            bg: '#f0fdf4',
            gradient: 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
        },
        'ERROR': {
            color: '#6b7280',
            icon: 'fa-times-circle',
            bg: '#f9fafb',
            gradient: 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)'
        },
        'UNKNOWN': {
            color: '#64748b',
            icon: 'fa-question-circle',
            bg: '#f8fafc',
            gradient: 'linear-gradient(135deg, #64748b 0%, #475569 100%)'
        }
    };
    
    return themes[level] || themes.UNKNOWN;
}

/**
 * Get category icon
 */
function getCategoryIcon(category) {
    const icons = {
        'Financial Services': 'fa-university',
        'Email/Authentication': 'fa-key',
        'E-commerce': 'fa-shopping-cart',
        'Government': 'fa-landmark',
        'Educational': 'fa-graduation-cap',
        'Social Media': 'fa-users',
        'General Website': 'fa-globe',
        'Technology': 'fa-code',
        'News/Media': 'fa-newspaper'
    };
    
    return icons[category] || 'fa-globe';
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    try {
        const date = new Date(dateString);
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        
        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        if (days < 7) return `${days}d ago`;
        
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
        });
    } catch (e) {
        return dateString;
    }
}

/**
 * Sanitize HTML to prevent XSS
 */
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Truncate URL for display
 */
function truncateURL(url, maxLength = 50) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
}

// ============================================================================
// INPUT HANDLERS
// ============================================================================

/**
 * Clear URL input
 */
function clearInput() {
    const input = document.getElementById('urlInput');
    if (input) {
        input.value = '';
        input.focus();
        document.getElementById('urlResults')?.classList.add('hidden');
    }
}

/**
 * Paste from clipboard
 */
async function pasteFromClipboard() {
    try {
        const text = await navigator.clipboard.readText();
        const input = document.getElementById('urlInput');
        if (input) {
            input.value = text.trim();
            showNotification('URL pasted from clipboard', 'success');
        }
    } catch (err) {
        showNotification('Failed to read clipboard. Please paste manually (Ctrl+V)', 'error');
    }
}

// ============================================================================
// MAIN ANALYSIS FUNCTION (FIXED)
// ============================================================================

/**
 * Analyze URL - Main entry point (FIXED: Button blocking)
 */
async function analyzeURL() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput?.value.trim();
    
    // Validation
    if (!url) {
        showNotification('Please enter a URL to analyze', 'error');
        urlInput?.focus();
        return;
    }
    
    // FIXED: Prevent duplicate analysis (REQUIREMENT #2)
    if (PhishGuard.state.isAnalyzing) {
        showNotification('Analysis already in progress. Please wait...', 'warning');
        return;
    }
    
    // FIXED: Block UI during analysis
    PhishGuard.state.isAnalyzing = true;
    const analyzeBtn = document.getElementById('analyzeBtn');
    const spinner = document.getElementById('loadingOverlay');
    const resultsDiv = document.getElementById('urlResults');
    
    // Disable button
    if (analyzeBtn) {
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = `
            <i class="fas fa-spinner fa-spin"></i>
            Analyzing...
        `;
    }
    
    if (spinner) spinner.classList.remove('hidden');
    if (resultsDiv) resultsDiv.classList.add('hidden');
    
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/analyze-url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        // FIXED: Handle different response types
        if (!response.ok) {
            if (response.status === 429) {
                showNotification('⏱️ Rate limit exceeded. Please wait a minute and try again.', 'error');
                renderRateLimitError();
                return;
            } else if (data.error) {
                throw new Error(data.error);
            } else {
                throw new Error(`Server returned ${response.status}`);
            }
        }
        
        if (data.success === false || data.error) {
            // URL validation error or unreachable
            throw new Error(data.error || data.verdict_summary || 'Analysis failed');
        }
        
        // Store result
        PhishGuard.state.lastAnalysis = data;
        
        // Render results
        renderAnalysisReport(data);
        
        if (resultsDiv) {
            resultsDiv.classList.remove('hidden');
            resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        
        // Reload dashboard data
        loadDashboardData();
        
        // Show success message
        const cacheMsg = data.from_cache 
            ? ` (Cached result from ${data.cache_age_minutes} minutes ago)` 
            : '';
        showNotification(`✅ Analysis complete!${cacheMsg}`, 'success');
        
    } catch (error) {
        console.error('Analysis error:', error);
        
        let errorMsg = 'Analysis failed. ';
        if (error.message.includes('Failed to fetch')) {
            errorMsg += 'Cannot connect to server. Please check if the server is running.';
        } else if (error.message.includes('timeout')) {
            errorMsg += 'Request timed out. The website may be slow or unreachable.';
        } else if (error.message.includes('NetworkError')) {
            errorMsg += 'Network error. Check your internet connection.';
        } else {
            errorMsg += error.message;
        }
        
        showNotification(errorMsg, 'error');
        renderErrorState(errorMsg);
        
    } finally {
        // FIXED: Always re-enable button (REQUIREMENT #2)
        PhishGuard.state.isAnalyzing = false;
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = `
                <i class="fas fa-search"></i>
                Analyze URL
            `;
        }
        if (spinner) spinner.classList.add('hidden');
    }
}

/**
 * Render rate limit error
 */
function renderRateLimitError() {
    const resultsDiv = document.getElementById('urlResults');
    if (!resultsDiv) return;
    
    resultsDiv.innerHTML = `
        <div class="bg-red-50 border-2 border-red-200 rounded-lg p-8 text-center">
            <i class="fas fa-clock text-6xl text-red-500 mb-4"></i>
            <h3 class="text-2xl font-bold text-red-700 mb-2">Rate Limit Exceeded</h3>
            <p class="text-red-600 mb-4">
                You've made too many requests. Please wait a minute before trying again.
            </p>
            <p class="text-sm text-red-500">
                This helps us keep the service fast and available for everyone.
            </p>
        </div>
    `;
    resultsDiv.classList.remove('hidden');
}

/**
 * Render error state
 */
function renderErrorState(errorMsg) {
    const resultsDiv = document.getElementById('urlResults');
    if (!resultsDiv) return;
    
    resultsDiv.innerHTML = `
        <div class="bg-gray-50 border-2 border-gray-200 rounded-lg p-8 text-center">
            <i class="fas fa-exclamation-triangle text-6xl text-gray-400 mb-4"></i>
            <h3 class="text-2xl font-bold text-gray-700 mb-2">Analysis Error</h3>
            <p class="text-gray-600 mb-4">${sanitizeHTML(errorMsg)}</p>
            <button onclick="clearInput()" class="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition">
                <i class="fas fa-redo mr-2"></i>
                Try Again
            </button>
        </div>
    `;
    resultsDiv.classList.remove('hidden');
}

// ============================================================================
// REPORT RENDERING
// ============================================================================

/**
 * Render complete analysis report
 */
function renderAnalysisReport(data) {
    const container = document.getElementById('urlResults');
    if (!container) return;
    
    const theme = getTheme(data.risk_level);
    const categoryIcon = getCategoryIcon(data.category);
    
    container.innerHTML = `
        ${renderHeroBanner(data, theme, categoryIcon)}
        ${renderScreenshot(data)}
        ${renderDetectionLogic(data, theme)}
        ${renderTechnicalSummary(data, theme)}
        ${renderActionButtons(data)}
        ${renderDisclaimer(data)}
    `;
}

/**
 * Render hero banner section
 */
function renderHeroBanner(data, theme, categoryIcon) {
    const riskScore = data.risk_score || 0;
    const confidence = data.confidence || 'UNKNOWN';
    const confidenceScore = data.confidence_score || 0;
    
    return `
        <div class="relative overflow-hidden rounded-t-2xl" style="background: ${theme.gradient};">
            <div class="absolute inset-0 opacity-10">
                <div class="absolute inset-0 bg-gradient-to-br from-white to-transparent"></div>
            </div>
            <div class="relative p-8 text-white">
                <div class="flex items-center justify-between mb-6">
                    <div>
                        <div class="inline-flex items-center gap-2 px-4 py-2 bg-white bg-opacity-20 rounded-full mb-3">
                            <i class="fas ${categoryIcon}"></i>
                            <span class="font-semibold">${sanitizeHTML(data.category || 'Unknown')}</span>
                        </div>
                        <h2 class="text-3xl font-bold mb-2">${sanitizeHTML(data.verdict_summary || 'Analysis Complete')}</h2>
                        <p class="text-white text-opacity-90 break-all">${sanitizeHTML(data.url)}</p>
                    </div>
                    <div class="text-center">
                        <div class="relative inline-flex items-center justify-center w-32 h-32">
                            <svg class="transform -rotate-90 w-32 h-32">
                                <circle cx="64" cy="64" r="56" stroke="currentColor" stroke-opacity="0.2" stroke-width="8" fill="none" />
                                <circle cx="64" cy="64" r="56" stroke="white" stroke-width="8" fill="none"
                                    stroke-dasharray="${2 * Math.PI * 56}"
                                    stroke-dashoffset="${2 * Math.PI * 56 * (1 - riskScore / 100)}"
                                    stroke-linecap="round" />
                            </svg>
                            <div class="absolute inset-0 flex flex-col items-center justify-center">
                                <span class="text-4xl font-bold">${riskScore}</span>
                                <span class="text-sm opacity-90">/ 100</span>
                            </div>
                        </div>
                        <p class="mt-2 text-sm">Risk Score</p>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4 mt-6">
                    <div class="bg-white bg-opacity-10 rounded-lg p-4">
                        <div class="text-sm opacity-90 mb-1">Risk Level</div>
                        <div class="text-2xl font-bold flex items-center gap-2">
                            <i class="fas ${theme.icon}"></i>
                            ${data.risk_level}
                        </div>
                    </div>
                    <div class="bg-white bg-opacity-10 rounded-lg p-4">
                        <div class="text-sm opacity-90 mb-1">Confidence</div>
                        <div class="text-2xl font-bold">${confidence} (${confidenceScore}%)</div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Render screenshot section
 */
function renderScreenshot(data) {
    if (!data.screenshot_url && !data.thumbnail_url) return '';
    
    const imageUrl = data.screenshot_url || data.thumbnail_url;
    
    return `
        <div class="bg-white border-x-2 border-gray-200 p-6">
            <h3 class="text-xl font-bold mb-4 flex items-center gap-2">
                <i class="fas fa-camera text-blue-500"></i>
                Website Screenshot
            </h3>
            <div class="relative group cursor-pointer" onclick="openScreenshotModal('${imageUrl}')">
                <img src="${imageUrl}" 
                     alt="Website screenshot" 
                     class="w-full rounded-lg shadow-lg transition-transform group-hover:scale-105"
                     onerror="this.parentElement.innerHTML='<div class=\'bg-gray-100 rounded-lg p-8 text-center text-gray-500\'>Screenshot not available</div>'">
                <div class="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-10 rounded-lg transition-all flex items-center justify-center">
                    <i class="fas fa-search-plus text-white text-3xl opacity-0 group-hover:opacity-100 transition-opacity"></i>
                </div>
            </div>
        </div>
    `;
}

/**
 * Render detection logic section
 */
function renderDetectionLogic(data, theme) {
    const dangerous = data.why_dangerous || [];
    const safe = data.why_safe || [];
    const signals = data.detected_signals || {};
    const activeSignals = Object.entries(signals).filter(([_, value]) => value);
    
    return `
        <div class="bg-white border-x-2 border-gray-200 p-6">
            <h3 class="text-xl font-bold mb-4 flex items-center gap-2">
                <i class="fas fa-brain text-purple-500"></i>
                Detection Logic
            </h3>
            
            ${dangerous.length > 0 ? `
                <div class="mb-6">
                    <h4 class="font-semibold text-red-600 mb-3 flex items-center gap-2">
                        <i class="fas fa-exclamation-triangle"></i>
                        Warning Signs (${dangerous.length})
                    </h4>
                    <ul class="space-y-2">
                        ${dangerous.map(warning => `
                            <li class="flex items-start gap-3 p-3 bg-red-50 rounded-lg">
                                <i class="fas fa-times-circle text-red-500 mt-1"></i>
                                <span class="text-gray-700">${sanitizeHTML(warning)}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${safe.length > 0 ? `
                <div class="mb-6">
                    <h4 class="font-semibold text-green-600 mb-3 flex items-center gap-2">
                        <i class="fas fa-check-circle"></i>
                        Trust Signals (${safe.length})
                    </h4>
                    <ul class="space-y-2">
                        ${safe.map(signal => `
                            <li class="flex items-start gap-3 p-3 bg-green-50 rounded-lg">
                                <i class="fas fa-check-circle text-green-500 mt-1"></i>
                                <span class="text-gray-700">${sanitizeHTML(signal)}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${activeSignals.length > 0 ? `
                <div>
                    <h4 class="font-semibold text-gray-700 mb-3 flex items-center gap-2">
                        <i class="fas fa-radar"></i>
                        Detected Patterns
                    </h4>
                    <div class="flex flex-wrap gap-2">
                        ${activeSignals.map(([key, _]) => {
                            const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                            return `
                                <span class="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm">
                                    <i class="fas fa-check text-blue-500 mr-1"></i>
                                    ${label}
                                </span>
                            `;
                        }).join('')}
                    </div>
                </div>
            ` : ''}
            
            ${data.action_guidance && data.action_guidance.length > 0 ? `
                <div class="mt-6 p-4 rounded-lg" style="background-color: ${theme.bg};">
                    <h4 class="font-semibold mb-3 flex items-center gap-2" style="color: ${theme.color};">
                        <i class="fas fa-lightbulb"></i>
                        Recommended Actions
                    </h4>
                    <ul class="space-y-2">
                        ${data.action_guidance.map(action => `
                            <li class="flex items-start gap-3">
                                <i class="fas fa-arrow-right mt-1" style="color: ${theme.color};"></i>
                                <span class="text-gray-700">${sanitizeHTML(action)}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;
}

/**
 * Render technical summary section
 */
function renderTechnicalSummary(data, theme) {
    const tech = data.technical_summary || {};
    const apis = data.api_results || {};
    const community = data.community_reports || {};
    const reputation = data.domain_reputation || {};
    
    return `
        <div class="bg-white border-x-2 border-gray-200 p-6">
            <h3 class="text-xl font-bold mb-4 flex items-center gap-2">
                <i class="fas fa-cog text-gray-600"></i>
                Technical Details
            </h3>
            
            <!-- Domain Information -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div class="p-4 bg-gray-50 rounded-lg">
                    <div class="text-sm text-gray-500 mb-1">Domain Age</div>
                    <div class="text-lg font-semibold text-gray-800">
                        ${tech.domain_age_days !== 'Unknown' ? tech.domain_age_days + ' days' : 'Unknown'}
                    </div>
                </div>
                <div class="p-4 bg-gray-50 rounded-lg">
                    <div class="text-sm text-gray-500 mb-1">Registrar</div>
                    <div class="text-lg font-semibold text-gray-800">
                        ${sanitizeHTML(tech.registrar || 'Unknown')}
                    </div>
                </div>
                <div class="p-4 bg-gray-50 rounded-lg">
                    <div class="text-sm text-gray-500 mb-1">SSL Status</div>
                    <div class="text-lg font-semibold ${tech.ssl_valid ? 'text-green-600' : 'text-red-600'}">
                        ${tech.ssl_valid ? '✓ Valid' : '✗ Invalid/Missing'}
                    </div>
                </div>
                <div class="p-4 bg-gray-50 rounded-lg">
                    <div class="text-sm text-gray-500 mb-1">Server IP</div>
                    <div class="text-lg font-semibold text-gray-800">
                        ${sanitizeHTML(tech.server_ip || 'Unknown')}
                    </div>
                </div>
            </div>
            
            <!-- SSL Certificate Details -->
            ${tech.ssl_valid ? `
                <div class="mb-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
                    <h4 class="font-semibold text-blue-800 mb-3">SSL Certificate Information</h4>
                    <div class="grid grid-cols-2 gap-3 text-sm">
                        <div>
                            <span class="text-blue-600">Issuer:</span>
                            <span class="ml-2 text-gray-700">${sanitizeHTML(tech.ssl_issuer || 'Unknown')}</span>
                        </div>
                        <div>
                            <span class="text-blue-600">Issued:</span>
                            <span class="ml-2 text-gray-700">${tech.ssl_issued_date || 'Unknown'}</span>
                        </div>
                        <div>
                            <span class="text-blue-600">Expires:</span>
                            <span class="ml-2 text-gray-700">${tech.ssl_expiry_date || 'Unknown'}</span>
                        </div>
                        <div>
                            <span class="text-blue-600">Age:</span>
                            <span class="ml-2 text-gray-700">
                                ${tech.ssl_cert_age_days !== 'Unknown' ? tech.ssl_cert_age_days + ' days' : 'Unknown'}
                            </span>
                        </div>
                    </div>
                </div>
            ` : ''}
            
            <!-- API Results -->
            ${Object.keys(apis).length > 0 ? `
                <div class="mb-6">
                    <h4 class="font-semibold text-gray-700 mb-3">External API Checks</h4>
                    <div class="space-y-2">
                        ${apis.google_safe_browsing ? `
                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                <span class="font-medium">Google Safe Browsing</span>
                                <span class="px-3 py-1 rounded-full text-sm ${
                                    apis.google_safe_browsing.status === 'safe' ? 'bg-green-100 text-green-700' :
                                    apis.google_safe_browsing.status === 'threat_found' ? 'bg-red-100 text-red-700' :
                                    'bg-gray-100 text-gray-700'
                                }">
                                    ${apis.google_safe_browsing.status === 'safe' ? '✓ Clean' :
                                      apis.google_safe_browsing.status === 'threat_found' ? '⚠ Threat Found' :
                                      '? Unknown'}
                                </span>
                            </div>
                        ` : ''}
                        ${apis.virustotal ? `
                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                <span class="font-medium">VirusTotal</span>
                                <span class="px-3 py-1 rounded-full text-sm ${
                                    apis.virustotal.detections === 0 ? 'bg-green-100 text-green-700' :
                                    apis.virustotal.detections > 0 ? 'bg-red-100 text-red-700' :
                                    'bg-gray-100 text-gray-700'
                                }">
                                    ${apis.virustotal.detections || 0}/${apis.virustotal.total_engines || 0} detections
                                </span>
                            </div>
                        ` : ''}
                    </div>
                </div>
            ` : ''}
            
            <!-- Community Reports -->
            ${community.total_reports > 0 ? `
                <div class="p-4 bg-yellow-50 rounded-lg border border-yellow-200">
                    <h4 class="font-semibold text-yellow-800 mb-3">Community Reports</h4>
                    <div class="grid grid-cols-3 gap-3 text-center text-sm">
                        <div>
                            <div class="text-2xl font-bold text-gray-700">${community.total_reports}</div>
                            <div class="text-gray-600">Total</div>
                        </div>
                        <div>
                            <div class="text-2xl font-bold text-red-600">${community.phishing_reports || 0}</div>
                            <div class="text-gray-600">Phishing</div>
                        </div>
                        <div>
                            <div class="text-2xl font-bold text-green-600">${community.safe_reports || 0}</div>
                            <div class="text-gray-600">Safe</div>
                        </div>
                    </div>
                </div>
            ` : ''}
            
            <!-- Domain Reputation -->
            ${reputation.total_scans > 0 ? `
                <div class="mt-4 p-4 bg-purple-50 rounded-lg border border-purple-200">
                    <h4 class="font-semibold text-purple-800 mb-3">Domain History</h4>
                    <div class="grid grid-cols-3 gap-3 text-sm">
                        <div>
                            <span class="text-purple-600">Total Scans:</span>
                            <span class="ml-2 font-semibold">${reputation.total_scans}</span>
                        </div>
                        <div>
                            <span class="text-purple-600">High Risk:</span>
                            <span class="ml-2 font-semibold">${reputation.high_risk_count || 0}</span>
                        </div>
                        <div>
                            <span class="text-purple-600">Avg Score:</span>
                            <span class="ml-2 font-semibold">${reputation.average_risk_score || 0}/100</span>
                        </div>
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

/**
 * Render action buttons
 */
function renderActionButtons(data) {
    return `
        <div class="bg-white border-x-2 border-b-2 border-gray-200 rounded-b-2xl p-6">
            <div class="flex flex-wrap gap-3 justify-center">
                <button onclick="downloadReport()" 
                    class="px-6 py-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition flex items-center gap-2">
                    <i class="fas fa-download"></i>
                    Download Report
                </button>
                <button onclick="shareReport()" 
                    class="px-6 py-3 bg-green-500 text-white rounded-lg hover:bg-green-600 transition flex items-center gap-2">
                    <i class="fas fa-share-alt"></i>
                    Share Results
                </button>
                <button onclick="submitReport('${sanitizeHTML(data.url)}', 'phishing')" 
                    class="px-6 py-3 bg-red-500 text-white rounded-lg hover:bg-red-600 transition flex items-center gap-2">
                    <i class="fas fa-flag"></i>
                    Report as Phishing
                </button>
                <button onclick="clearInput()" 
                    class="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition flex items-center gap-2">
                    <i class="fas fa-redo"></i>
                    Analyze Another
                </button>
            </div>
        </div>
    `;
}

/**
 * Render disclaimer
 */
function renderDisclaimer(data) {
    const analysisTime = data.analysis_time_seconds || 'N/A';
    const fromCache = data.from_cache ? 'Yes' : 'No';
    
    return `
        <div class="mt-4 p-4 bg-gray-50 rounded-lg border border-gray-200 text-sm text-gray-600">
            <p class="mb-2">
                <strong>Disclaimer:</strong> This analysis is automated and should be used as a guide only. 
                Always exercise caution when visiting unfamiliar websites and verify legitimacy through official channels.
            </p>
            <p class="text-xs text-gray-500">
                Analysis Time: ${analysisTime}s | From Cache: ${fromCache} | 
                Timestamp: ${new Date().toLocaleString()}
            </p>
        </div>
    `;
}

/**
 * Open screenshot in modal
 */
function openScreenshotModal(imageUrl) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-75 z-50 flex items-center justify-center p-4';
    modal.onclick = () => modal.remove();
    
    modal.innerHTML = `
        <div class="relative max-w-6xl max-h-full">
            <button class="absolute -top-10 right-0 text-white text-2xl hover:text-gray-300">
                <i class="fas fa-times"></i>
            </button>
            <img src="${imageUrl}" 
                 alt="Full screenshot" 
                 class="max-w-full max-h-screen rounded-lg shadow-2xl"
                 onclick="event.stopPropagation()">
        </div>
    `;
    
    document.body.appendChild(modal);
}

// ============================================================================
// REPORT ACTIONS
// ============================================================================

/**
 * Submit report to server
 */
async function submitReport(url, reportType = 'phishing') {
    const comment = prompt('Optional: Add a comment about this URL');
    
    if (comment === null) return; // User cancelled
    
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: url,
                report_type: reportType,
                comment: comment
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Thank you! Your report has been submitted.', 'success');
        } else {
            throw new Error(data.error || 'Failed to submit report');
        }
        
    } catch (error) {
        console.error('Report submission error:', error);
        showNotification('Failed to submit report. Please try again.', 'error');
    }
}

/**
 * Download analysis report
 */
function downloadReport() {
    const data = PhishGuard.state.lastAnalysis;
    if (!data) {
        showNotification('No analysis data available', 'error');
        return;
    }
    
    // Create detailed text report
    let report = '═══════════════════════════════════════════════════════════\n';
    report += '               PHISHGUARD ANALYSIS REPORT\n';
    report += '═══════════════════════════════════════════════════════════\n\n';
    
    report += 'URL ANALYZED:\n';
    report += `${data.url}\n\n`;
    
    report += 'VERDICT:\n';
    report += `${data.verdict_summary}\n\n`;
    
    report += 'RISK ASSESSMENT:\n';
    report += `Risk Level: ${data.risk_level}\n`;
    report += `Risk Score: ${data.risk_score}/100\n`;
    report += `Confidence: ${data.confidence} (${data.confidence_score}%)\n`;
    report += `Category: ${data.category}\n\n`;
    
    if (data.why_dangerous && data.why_dangerous.length > 0) {
        report += 'WARNING SIGNS:\n';
        data.why_dangerous.forEach((warning, i) => {
            report += `${i + 1}. ${warning}\n`;
        });
        report += '\n';
    }
    
    if (data.why_safe && data.why_safe.length > 0) {
        report += 'TRUST SIGNALS:\n';
        data.why_safe.forEach((signal, i) => {
            report += `${i + 1}. ${signal}\n`;
        });
        report += '\n';
    }
    
    if (data.action_guidance && data.action_guidance.length > 0) {
        report += 'RECOMMENDED ACTIONS:\n';
        data.action_guidance.forEach((action, i) => {
            report += `${i + 1}. ${action}\n`;
        });
        report += '\n';
    }
    
    const tech = data.technical_summary || {};
    report += 'TECHNICAL DETAILS:\n';
    report += `Domain Age: ${tech.domain_age_days !== 'Unknown' ? tech.domain_age_days + ' days' : 'Unknown'}\n`;
    report += `SSL Status: ${tech.ssl_valid ? 'Valid' : 'Invalid'}\n`;
    report += `SSL Issuer: ${tech.ssl_issuer || 'Unknown'}\n`;
    report += `Registrar: ${tech.registrar || 'Unknown'}\n`;
    report += `Server IP: ${tech.server_ip || 'Unknown'}\n\n`;
    
    report += '═══════════════════════════════════════════════════════════\n';
    report += `Generated: ${new Date().toLocaleString()}\n`;
    report += `Analysis Time: ${data.analysis_time_seconds || 'N/A'} seconds\n`;
    report += 'PhishGuard - Educational Tool by Kuldeep & Aman Tiwari\n';
    report += '═══════════════════════════════════════════════════════════\n';
    
    // Create and download file
    const blob = new Blob([report], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-report-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showNotification('Report downloaded successfully', 'success');
}

/**
 * Share analysis results
 */
function shareReport() {
    const data = PhishGuard.state.lastAnalysis;
    if (!data) {
        showNotification('No analysis data available', 'error');
        return;
    }
    
    const shareText = `PhishGuard Analysis Results\n\nURL: ${data.url}\nRisk Level: ${data.risk_level}\nRisk Score: ${data.risk_score}/100\n\n${data.verdict_summary}\n\nAnalyzed with PhishGuard - https://phishguard.app`;
    
    if (navigator.share) {
        navigator.share({
            title: 'PhishGuard Analysis Results',
            text: shareText
        }).catch(err => {
            if (err.name !== 'AbortError') {
                copyToClipboard(shareText);
            }
        });
    } else {
        copyToClipboard(shareText);
    }
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Results copied to clipboard!', 'success');
        }).catch(() => {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

/**
 * Fallback copy method
 */
function fallbackCopy(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    document.body.appendChild(textArea);
    textArea.select();
    
    try {
        document.execCommand('copy');
        showNotification('Results copied to clipboard!', 'success');
    } catch (err) {
        showNotification('Failed to copy. Please copy manually.', 'error');
    }
    
    document.body.removeChild(textArea);
}

// ============================================================================
// BATCH ANALYSIS
// ============================================================================

/**
 * Analyze multiple URLs
 */
async function analyzeBatch() {
    const textarea = document.getElementById('batchUrls');
    const urls = textarea?.value.split('\n')
        .map(url => url.trim())
        .filter(url => url && url.length > 0);
    
    if (!urls || urls.length === 0) {
        showNotification('Please enter at least one URL', 'error');
        return;
    }
    
    if (urls.length > PhishGuard.config.MAX_BATCH_URLS) {
        showNotification(`Maximum ${PhishGuard.config.MAX_BATCH_URLS} URLs allowed`, 'error');
        return;
    }
    
    const btn = document.getElementById('analyzeBatchBtn');
    const resultsDiv = document.getElementById('batchResults');
    
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Analyzing...';
    }
    
    const results = [];
    
    for (let i = 0; i < urls.length; i++) {
        try {
            showNotification(`Analyzing ${i + 1}/${urls.length}: ${truncateURL(urls[i])}`, 'info');
            
            const response = await fetch(`${PhishGuard.config.API_BASE}/api/analyze-url`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: urls[i] })
            });
            
            const data = await response.json();
            
            if (response.ok && !data.error) {
                results.push({ url: urls[i], success: true, data });
            } else {
                results.push({ url: urls[i], success: false, error: data.error || 'Unknown error' });
            }
            
        } catch (error) {
            results.push({ url: urls[i], success: false, error: error.message });
        }
        
        // Small delay to avoid rate limiting
        if (i < urls.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    
    renderBatchResults(results);
    
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-bolt mr-2"></i>Analyze Batch';
    }
    
    if (resultsDiv) {
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    showNotification(`Batch analysis complete! ${results.filter(r => r.success).length}/${results.length} successful`, 'success');
}

/**
 * Render batch analysis results
 */
function renderBatchResults(results) {
    const container = document.getElementById('batchResults');
    if (!container) return;
    
    const successCount = results.filter(r => r.success).length;
    const highRiskCount = results.filter(r => r.success && (r.data.risk_level === 'CRITICAL' || r.data.risk_level === 'HIGH')).length;
    
    let html = `
        <div class="mb-6">
            <h3 class="text-2xl font-bold mb-4">Batch Analysis Results</h3>
            <div class="grid grid-cols-3 gap-4 mb-6">
                <div class="p-4 bg-blue-50 rounded-lg border border-blue-200 text-center">
                    <div class="text-3xl font-bold text-blue-600">${results.length}</div>
                    <div class="text-sm text-gray-600">Total URLs</div>
                </div>
                <div class="p-4 bg-green-50 rounded-lg border border-green-200 text-center">
                    <div class="text-3xl font-bold text-green-600">${successCount}</div>
                    <div class="text-sm text-gray-600">Analyzed</div>
                </div>
                <div class="p-4 bg-red-50 rounded-lg border border-red-200 text-center">
                    <div class="text-3xl font-bold text-red-600">${highRiskCount}</div>
                    <div class="text-sm text-gray-600">High Risk</div>
                </div>
            </div>
        </div>
        
        <div class="space-y-4">
    `;
    
    results.forEach((result, index) => {
        if (result.success) {
            const theme = getTheme(result.data.risk_level);
            html += `
                <div class="border-2 rounded-lg overflow-hidden" style="border-color: ${theme.color};">
                    <div class="p-4" style="background: ${theme.bg};">
                        <div class="flex items-center justify-between">
                            <div class="flex-1">
                                <div class="flex items-center gap-3 mb-2">
                                    <span class="px-3 py-1 rounded-full text-white text-sm font-semibold" 
                                          style="background: ${theme.color};">
                                        ${result.data.risk_level}
                                    </span>
                                    <span class="text-gray-600 font-medium">${result.data.risk_score}/100</span>
                                </div>
                                <p class="text-sm text-gray-700 break-all">${sanitizeHTML(result.url)}</p>
                            </div>
                            <i class="fas ${theme.icon} text-3xl" style="color: ${theme.color};"></i>
                        </div>
                    </div>
                </div>
            `;
        } else {
            html += `
                <div class="border-2 border-gray-300 rounded-lg p-4 bg-gray-50">
                    <div class="flex items-center justify-between">
                        <div class="flex-1">
                            <div class="flex items-center gap-2 mb-2">
                                <span class="px-3 py-1 bg-red-100 text-red-700 rounded-full text-sm font-semibold">
                                    ERROR
                                </span>
                            </div>
                            <p class="text-sm text-gray-700 break-all mb-1">${sanitizeHTML(result.url)}</p>
                            <p class="text-xs text-red-600">${sanitizeHTML(result.error)}</p>
                        </div>
                        <i class="fas fa-times-circle text-3xl text-red-500"></i>
                    </div>
                </div>
            `;
        }
    });
    
    html += '</div>';
    
    container.innerHTML = html;
    container.classList.remove('hidden');
}

// ============================================================================
// DASHBOARD & STATISTICS
// ============================================================================

/**
 * Load and display statistics
 */
async function loadStatistics() {
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/history?limit=100`);
        if (!response.ok) return;
        
        const data = await response.json();
        const history = data.history || [];
        
        if (history.length === 0) return;
        
        // Calculate stats
        const totalScans = history.length;
        const highRisk = history.filter(h => h.risk_level === 'CRITICAL' || h.risk_level === 'HIGH').length;
        const avgRisk = Math.round(history.reduce((sum, h) => sum + (h.risk_score || 0), 0) / totalScans);
        const uniqueDomains = new Set(history.map(h => h.domain)).size;
        
        // Update cards
        updateStatCard('totalScans', totalScans);
        updateStatCard('highRiskCount', highRisk);
        updateStatCard('avgRiskScore', avgRisk);
        updateStatCard('uniqueDomains', uniqueDomains);
        
    } catch (error) {
        console.error('Failed to load statistics:', error);
    }
}

/**
 * Update stat card with animation
 */
function updateStatCard(id, value) {
    const element = document.getElementById(id);
    if (!element) return;
    
    const current = parseInt(element.textContent) || 0;
    animateNumber(element, current, value, 1000);
}

/**
 * Animate number change
 */
function animateNumber(element, start, end, duration) {
    const startTime = Date.now();
    const difference = end - start;
    
    function update() {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const easeOutQuart = 1 - Math.pow(1 - progress, 4);
        const current = Math.round(start + difference * easeOutQuart);
        
        element.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

// ============================================================================
// HISTORY MANAGEMENT
// ============================================================================

/**
 * Load scan history
 */
async function loadHistory(riskLevel = null) {
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/history`);
        if (!response.ok) throw new Error('Failed to load history');
        
        const data = await response.json();
        let history = data.history || [];
        
        // Filter by risk level if specified
        if (riskLevel) {
            history = history.filter(h => h.risk_level === riskLevel);
        }
        
        PhishGuard.state.historyData = history;
        renderHistory(history);
        
    } catch (error) {
        console.error('Failed to load history:', error);
        const container = document.getElementById('historyList');
        if (container) {
            container.innerHTML = `
                <div class="text-center py-12 text-gray-500">
                    <i class="fas fa-exclamation-triangle text-4xl mb-3"></i>
                    <p>Failed to load history</p>
                </div>
            `;
        }
    }
}

/**
 * Render history list
 */
function renderHistory(history) {
    const container = document.getElementById('historyList');
    if (!container) return;
    
    if (history.length === 0) {
        container.innerHTML = `
            <div class="text-center py-12 text-gray-500">
                <i class="fas fa-history text-4xl mb-3"></i>
                <p>No scan history available</p>
                <p class="text-sm">Analyze some URLs to see them here</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="space-y-3">';
    
    history.forEach(scan => {
        const theme = getTheme(scan.risk_level);
        const categoryIcon = getCategoryIcon(scan.context);
        
        html += `
            <div class="border-l-4 bg-white rounded-r-lg p-4 hover:shadow-lg transition cursor-pointer"
                 style="border-color: ${theme.color};"
                 onclick="viewScanDetails('${scan.id}')">
                <div class="flex items-center justify-between">
                    <div class="flex-1">
                        <div class="flex items-center gap-3 mb-2">
                            <i class="fas ${categoryIcon} text-gray-400"></i>
                            <span class="px-2 py-1 text-xs rounded-full text-white font-semibold"
                                  style="background: ${theme.color};">
                                ${scan.risk_level}
                            </span>
                            <span class="text-sm text-gray-500">${scan.risk_score}/100</span>
                        </div>
                        <p class="text-sm text-gray-700 font-medium truncate">${sanitizeHTML(scan.domain || scan.url)}</p>
                        <p class="text-xs text-gray-500 mt-1">${formatDate(scan.timestamp)}</p>
                    </div>
                    <i class="fas fa-chevron-right text-gray-400"></i>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

/**
 * View scan details from history
 */
async function viewScanDetails(scanId) {
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/scan/${scanId}`);
        if (!response.ok) throw new Error('Failed to load scan details');
        
        const data = await response.json();
        
        // Store as last analysis
        PhishGuard.state.lastAnalysis = data;
        
        // Switch to scanner tab and show results
        switchTab('scanner');
        renderAnalysisReport(data);
        
        const resultsDiv = document.getElementById('urlResults');
        if (resultsDiv) {
            resultsDiv.classList.remove('hidden');
            resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        
    } catch (error) {
        console.error('Failed to load scan details:', error);
        showNotification('Failed to load scan details', 'error');
    }
}

/**
 * Search history
 */
async function searchHistory() {
    const searchInput = document.getElementById('historySearch');
    const query = searchInput?.value.trim();
    
    if (!query) {
        loadHistory();
        return;
    }
    
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/search?q=${encodeURIComponent(query)}`);
        if (!response.ok) throw new Error('Search failed');
        
        const data = await response.json();
        const results = data.results || [];
        
        renderHistory(results);
        
    } catch (error) {
        console.error('Search failed:', error);
        showNotification('Search failed', 'error');
    }
}

/**
 * Filter history by risk level
 */
function filterHistory(level) {
    if (!level) {
        loadHistory();
    } else {
        const filtered = PhishGuard.state.historyData.filter(h => h.risk_level === level);
        renderHistory(filtered);
    }
}

// ============================================================================
// TAB MANAGEMENT
// ============================================================================

/**
 * Switch between tabs
 */
function switchTab(tabName) {
    // Update state
    PhishGuard.state.currentTab = tabName;
    
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.add('hidden');
    });
    
    // Remove active class from all tab buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active', 'border-blue-500', 'text-blue-600');
        btn.classList.add('border-transparent', 'text-gray-500');
    });
    
    // Show selected tab
    const tabContent = document.getElementById(`${tabName}Tab`);
    if (tabContent) {
        tabContent.classList.remove('hidden');
    }
    
    // Activate selected tab button
    const tabButton = document.querySelector(`[onclick="switchTab('${tabName}')"]`);
    if (tabButton) {
        tabButton.classList.remove('border-transparent', 'text-gray-500');
        tabButton.classList.add('active', 'border-blue-500', 'text-blue-600');
    }
    
    // Load data for specific tabs
    if (tabName === 'history') {
        loadHistory();
    } else if (tabName === 'dashboard') {
        loadDashboardData();
    } else if (tabName === 'quiz') {
        if (PhishGuard.quiz.questions.length === 0) {
            loadQuizQuestions();
        }
    }
}

// ============================================================================
// QUIZ FUNCTIONALITY
// ============================================================================

/**
 * Initialize quiz
 */
function initializeQuiz() {
    PhishGuard.quiz.questions = [];
    PhishGuard.quiz.currentIndex = 0;
    PhishGuard.quiz.userAnswers = [];
    PhishGuard.quiz.score = 0;
}

/**
 * Load quiz questions
 */
function loadQuizQuestions() {
    // Shuffle questions
    const shuffled = [...QUIZ_QUESTIONS].sort(() => Math.random() - 0.5);
    PhishGuard.quiz.questions = shuffled.slice(0, 10);
    PhishGuard.quiz.currentIndex = 0;
    PhishGuard.quiz.userAnswers = [];
    PhishGuard.quiz.score = 0;
    
    displayQuizQuestion();
}

/**
 * Display current quiz question
 */
function displayQuizQuestion() {
    const container = document.getElementById('quizContainer');
    if (!container) return;
    
    const currentQ = PhishGuard.quiz.questions[PhishGuard.quiz.currentIndex];
    const questionNumber = PhishGuard.quiz.currentIndex + 1;
    const totalQuestions = PhishGuard.quiz.questions.length;
    
    if (!currentQ) {
        loadQuizQuestions();
        return;
    }
    
    const progress = (questionNumber / totalQuestions) * 100;
    
    container.innerHTML = `
        <div class="bg-white rounded-2xl shadow-xl p-8">
            <!-- Progress -->
            <div class="mb-6">
                <div class="flex justify-between text-sm mb-2">
                    <span class="font-semibold text-gray-700">Question ${questionNumber} of ${totalQuestions}</span>
                    <span class="text-gray-500">${Math.round(progress)}%</span>
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2">
                    <div class="bg-blue-500 h-2 rounded-full transition-all duration-300" 
                         style="width: ${progress}%"></div>
                </div>
            </div>
            
            <!-- Question -->
            <div class="mb-8">
                <h3 class="text-2xl font-bold text-gray-800 mb-4">${sanitizeHTML(currentQ.question)}</h3>
            </div>
            
            <!-- Options -->
            <div class="space-y-3 mb-8">
                ${currentQ.options.map((option, index) => `
                    <button id="quizOption${index}"
                        onclick="selectQuizAnswer('${sanitizeHTML(option)}', 'quizOption${index}')"
                        class="w-full p-4 text-left border-2 border-gray-200 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition">
                        <span class="font-medium text-gray-800">${sanitizeHTML(option)}</span>
                    </button>
                `).join('')}
            </div>
            
            <!-- Next Button -->
            <button id="nextQuizBtn" 
                onclick="nextQuestion()" 
                disabled
                class="w-full py-3 bg-gray-300 text-gray-500 rounded-lg cursor-not-allowed transition">
                Next Question
            </button>
        </div>
    `;
}

/**
 * Select quiz answer
 */
function selectQuizAnswer(answer, buttonId) {
    // Store answer
    PhishGuard.quiz.userAnswers[PhishGuard.quiz.currentIndex] = answer;
    
    // Highlight selected option
    document.querySelectorAll('[id^="quizOption"]').forEach(btn => {
        btn.classList.remove('border-blue-500', 'bg-blue-50');
        btn.classList.add('border-gray-200');
    });
    
    const selected = document.getElementById(buttonId);
    if (selected) {
        selected.classList.remove('border-gray-200');
        selected.classList.add('border-blue-500', 'bg-blue-50');
    }
    
    // Enable next button
    const nextBtn = document.getElementById('nextQuizBtn');
    if (nextBtn) {
        nextBtn.disabled = false;
        nextBtn.classList.remove('bg-gray-300', 'text-gray-500', 'cursor-not-allowed');
        nextBtn.classList.add('bg-blue-500', 'text-white', 'hover:bg-blue-600', 'cursor-pointer');
    }
}

/**
 * Go to next question
 */
function nextQuestion() {
    PhishGuard.quiz.currentIndex++;
    
    if (PhishGuard.quiz.currentIndex >= PhishGuard.quiz.questions.length) {
        showQuizResults();
    } else {
        displayQuizQuestion();
    }
}

/**
 * Show quiz results
 */
function showQuizResults() {
    // Calculate score
    PhishGuard.quiz.score = 0;
    PhishGuard.quiz.questions.forEach((q, i) => {
        if (PhishGuard.quiz.userAnswers[i] === q.answer) {
            PhishGuard.quiz.score++;
        }
    });
    
    const container = document.getElementById('quizContainer');
    if (!container) return;
    
    const percentage = Math.round((PhishGuard.quiz.score / PhishGuard.quiz.questions.length) * 100);
    const passed = percentage >= 70;
    
    container.innerHTML = `
        <div class="bg-white rounded-2xl shadow-xl p-8 text-center">
            <div class="mb-6">
                ${passed 
                    ? '<i class="fas fa-trophy text-7xl text-yellow-500 mb-4"></i>'
                    : '<i class="fas fa-graduation-cap text-7xl text-blue-500 mb-4"></i>'
                }
            </div>
            
            <h2 class="text-3xl font-bold mb-4 ${passed ? 'text-green-600' : 'text-blue-600'}">
                ${passed ? 'Congratulations!' : 'Good Effort!'}
            </h2>
            
            <div class="mb-8">
                <div class="text-6xl font-bold ${passed ? 'text-green-600' : 'text-blue-600'} mb-2">
                    ${percentage}%
                </div>
                <p class="text-gray-600">
                    You scored ${PhishGuard.quiz.score} out of ${PhishGuard.quiz.questions.length}
                </p>
            </div>
            
            <div class="mb-8 p-6 bg-gray-50 rounded-lg">
                <h3 class="font-bold text-gray-800 mb-4">Performance</h3>
                <div class="w-full bg-gray-200 rounded-full h-4">
                    <div class="h-4 rounded-full transition-all duration-1000 ${
                        percentage >= 90 ? 'bg-green-500' :
                        percentage >= 70 ? 'bg-blue-500' :
                        percentage >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                    }" style="width: ${percentage}%"></div>
                </div>
            </div>
            
            ${!passed ? `
                <p class="text-gray-600 mb-6">
                    Keep learning! Review the awareness page to improve your phishing detection skills.
                </p>
            ` : `
                <p class="text-gray-600 mb-6">
                    Excellent! You have a strong understanding of phishing detection.
                </p>
            `}
            
            <div class="flex gap-4 justify-center">
                <button onclick="restartQuiz()" 
                    class="px-6 py-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition">
                    <i class="fas fa-redo mr-2"></i>
                    Try Again
                </button>
                <button onclick="switchTab('awareness')" 
                    class="px-6 py-3 bg-green-500 text-white rounded-lg hover:bg-green-600 transition">
                    <i class="fas fa-book mr-2"></i>
                    Learn More
                </button>
            </div>
        </div>
    `;
}

/**
 * Restart quiz
 */
function restartQuiz() {
    initializeQuiz();
    loadQuizQuestions();
}

// ============================================================================
// ANIMATIONS & STYLES
// ============================================================================

// Add animation styles
const animationStyles = document.createElement('style');
animationStyles.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
`;
document.head.appendChild(animationStyles);

// ============================================================================
// WINDOW EVENT LISTENERS
// ============================================================================

// Prevent analyzing state from persisting on reload
window.addEventListener('beforeunload', () => {
    PhishGuard.state.isAnalyzing = false;
});

// Handle online/offline status
window.addEventListener('online', () => {
    showNotification('Back online!', 'success');
});

window.addEventListener('offline', () => {
    showNotification('You are offline. Some features may not work.', 'warning');
});

console.log('✅ PhishGuard v2.0 Fully Loaded!');
