/**
 * DOM Event Monitoring Script for Globomantics E-Commerce
 * 
 * This script demonstrates how to monitor DOM events and client-side storage
 * to detect data leakage in web applications.
 *
 * For use in Challenge 4 of the DOM-Based Security Testing with ZAP lab.
 */

class DOMSecurityMonitor {
    constructor() {
        this.detectedEvents = [];
        this.sensitiveDataPatterns = {
            creditCard: /\b(?:\d{4}[ -]?){3}\d{4}\b/,
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
            password: /password['":\s]*[^,\s}{]+/i,
            sessionTokens: /token['":\s]*[^,\s}{]+/i,
            // Added patterns for new vulnerabilities
            usernames: /username['":\s]*[^,\s}{]+/i,
            searchQueries: /"query":\s*"([^"]*)"/i,
            adminData: /"role":\s*"admin"/i,
            cssInjection: /javascript:|expression\s*\(/i,
            scriptTags: /<\s*script[^>]*>/i,
            evalUsage: /eval\s*\(/i,
            documentWrite: /document\.write/i,
            innerHTML: /innerHTML\s*=/i,
            hashExploitation: /#.*[<>'"]/i
        };
        
        // Track DOM XSS vulnerabilities discovered
        this.domXssVulnerabilities = [];
        
        // Track postMessage vulnerabilities
        this.postMessageVulnerabilities = [];
        
        // Track script injection vulnerabilities
        this.scriptInjectionVulnerabilities = [];
        
        // Track URL parameter vulnerabilities
        this.urlParameterVulnerabilities = [];
    }

    startMonitoring() {
        console.log("DOM Security Monitor started");
        this.monitorDOMEvents();
        this.monitorClientStorage();
        this.monitorXHR();
        this.monitorPostMessages();
        this.monitorDynamicScriptLoading();
        this.monitorURLParameters();
        this.monitorDOMModification();
        this.monitorEvalUsage();
        this.displayMonitorStatus();
        
        // Set up periodic checks
        setInterval(() => this.periodicCheck(), 5000);
    }

    monitorDOMEvents() {
        // Monitor custom events that might contain sensitive data
        const eventsToMonitor = [
            'userSearch', 'cartUpdated', 'orderPlaced', 'userFeedback', 
            'adminAction', 'newsLetterSignup', 'productView', 'checkoutProcess'
        ];
        
        eventsToMonitor.forEach(eventType => {
            document.addEventListener(eventType, (e) => {
                console.log(`[DOM Event] Detected ${eventType} event:`, e.detail);
                
                // Check for sensitive data in event details
                this.scanForSensitiveData(JSON.stringify(e.detail), eventType);
                
                this.detectedEvents.push({
                    type: eventType,
                    timestamp: new Date().toISOString(),
                    hasDataLeakage: this.checkForDataLeakage(e.detail)
                });
            });
        });
    }

    monitorClientStorage() {
        // Monitor localStorage and sessionStorage
        const originalSetItem = localStorage.setItem;
        localStorage.setItem = (key, value) => {
            console.log(`[Storage] localStorage.setItem('${key}', '${this.truncate(value)}')`, value);
            this.scanForSensitiveData(value, `localStorage[${key}]`);
            originalSetItem.call(localStorage, key, value);
        };
        
        const originalSessionSetItem = sessionStorage.setItem;
        sessionStorage.setItem = (key, value) => {
            console.log(`[Storage] sessionStorage.setItem('${key}', '${this.truncate(value)}')`, value);
            this.scanForSensitiveData(value, `sessionStorage[${key}]`);
            originalSessionSetItem.call(sessionStorage, key, value);
        };
        
        // Check existing storage entries
        this.checkExistingStorage();
    }
    
    monitorXHR() {
        // Monitor XMLHttpRequest for data leakage
        const originalOpen = XMLHttpRequest.prototype.open;
        const originalSend = XMLHttpRequest.prototype.send;
        
        XMLHttpRequest.prototype.open = function(method, url) {
            this._url = url;
            this._method = method;
            return originalOpen.apply(this, arguments);
        };
        
        XMLHttpRequest.prototype.send = function(data) {
            if (data) {
                console.log(`[XHR] ${this._method} ${this._url}`, data);
                // Check for sensitive data in XHR requests
                this.scanForSensitiveData(data, `XHR[${this._url}]`);
            }
            return originalSend.apply(this, arguments);
        }.bind(this);
    }
    
    monitorPostMessages() {
        // Monitor postMessage for potential vulnerabilities
        window.addEventListener('message', (event) => {
            console.log(`[PostMessage] Received message from ${event.origin}:`, event.data);
            
            // Check if origin validation is missing
            if (event.origin !== 'http://localhost:3000') {
                this.postMessageVulnerabilities.push({
                    timestamp: new Date().toISOString(),
                    origin: event.origin,
                    data: this.truncate(JSON.stringify(event.data)),
                    vulnerability: 'Missing origin validation in postMessage'
                });
                
                console.warn('[VULNERABILITY] postMessage received without proper origin validation');
            }
            
            // Check for dangerous content types in received messages
            if (event.data && typeof event.data === 'object') {
                if (event.data.type === 'execute_code' || 
                    event.data.type === 'inject_content' || 
                    event.data.code) {
                    
                    this.postMessageVulnerabilities.push({
                        timestamp: new Date().toISOString(),
                        origin: event.origin,
                        data: this.truncate(JSON.stringify(event.data)),
                        vulnerability: 'Dangerous postMessage content type'
                    });
                    
                    console.warn('[VULNERABILITY] Dangerous postMessage content type detected');
                }
            }
            
            // Check for sensitive data in postMessage
            this.scanForSensitiveData(JSON.stringify(event.data), 'postMessage');
        });
    }
    
    monitorDynamicScriptLoading() {
        // Monitor dynamic script creation
        const originalCreateElement = document.createElement;
        document.createElement = function(tagName) {
            const element = originalCreateElement.call(document, tagName);
            
            if (tagName.toLowerCase() === 'script') {
                // Override the src property setter
                let originalSrc = '';
                Object.defineProperty(element, 'src', {
                    set: function(value) {
                        console.log(`[Script] Dynamic script loading: ${value}`);
                        
                        // Check if the script source is controlled by user input
                        if (value.includes('?') && value.includes('=')) {
                            this.scriptInjectionVulnerabilities.push({
                                timestamp: new Date().toISOString(),
                                src: value,
                                vulnerability: 'Dynamic script loading with URL parameters'
                            });
                            
                            console.warn('[VULNERABILITY] Dynamic script loading with URL parameters');
                        }
                        
                        originalSrc = value;                    }.bind(this),
                    get: function() {
                        return originalSrc;
                    }
                });
            }
            
            return element;
        }.bind(this);
    }
    
    monitorURLParameters() {
        // Monitor URL parameters and hash for vulnerabilities
        const checkUrl = () => {
            const url = window.location.href;
            const urlParams = new URLSearchParams(window.location.search);
            const hash = window.location.hash;
            
            // Check URL parameters for XSS
            for (const [key, value] of urlParams.entries()) {
                if (this.sensitiveDataPatterns.scriptTags.test(value) || 
                    this.sensitiveDataPatterns.cssInjection.test(value)) {
                    
                    this.urlParameterVulnerabilities.push({
                        timestamp: new Date().toISOString(),
                        parameter: key,
                        value: value,
                        vulnerability: 'XSS in URL parameter'
                    });
                    
                    console.warn(`[VULNERABILITY] Potential XSS in URL parameter '${key}': ${value}`);
                }
            }
            
            // Check hash for XSS
            if (this.sensitiveDataPatterns.hashExploitation.test(hash) || 
                this.sensitiveDataPatterns.scriptTags.test(hash) || 
                hash.includes('javascript:')) {
                
                this.urlParameterVulnerabilities.push({
                    timestamp: new Date().toISOString(),
                    hash: hash,
                    vulnerability: 'XSS in URL hash'
                });
                
                console.warn(`[VULNERABILITY] Potential XSS in URL hash: ${hash}`);
            }
        };
        
        // Check on initialization
        checkUrl();
        
        // Monitor URL changes
        window.addEventListener('hashchange', checkUrl);
        
        // Monitor pushState and replaceState
        const originalPushState = history.pushState;
        const originalReplaceState = history.replaceState;
        
        history.pushState = function() {
            originalPushState.apply(history, arguments);
            checkUrl();
        };
        
        history.replaceState = function() {
            originalReplaceState.apply(history, arguments);
            checkUrl();
        };
    }
    
    monitorDOMModification() {
        // Monitor innerHTML and outerHTML assignments
        const monitorElementProperty = (element, prop) => {
            const originalDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, prop);
            
            Object.defineProperty(element, prop, {
                set: function(value) {
                    console.log(`[DOM] ${element.tagName}.${prop} = ${this.truncate(value)}`);
                    
                    // Check for potentially dangerous content
                    if (this.sensitiveDataPatterns.scriptTags.test(value) || 
                        value.includes('javascript:') || 
                        value.includes('data:') && value.includes('base64')) {
                        
                        this.domXssVulnerabilities.push({
                            timestamp: new Date().toISOString(),
                            element: element.tagName,
                            property: prop,
                            value: this.truncate(value),
                            vulnerability: 'Potentially dangerous content assigned to DOM property'
                        });
                        
                        console.warn(`[VULNERABILITY] Potentially dangerous content assigned to ${element.tagName}.${prop}`);
                    }
                    
                    // Call the original setter                    originalDescriptor.set.call(element, value);
                },
                get: function() {
                    return originalDescriptor.get.call(element);
                }
            });
        };
        
        // Monitor createElement and appendChild
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach(node => {                        if (node.nodeType === 1) { // Element node
                            this.monitorElementProperty(node, 'innerHTML');
                            this.monitorElementProperty(node, 'outerHTML');
                        }
                    });
                }
            });
        });
        
        observer.observe(document, { childList: true, subtree: true });
    }
    
    monitorEvalUsage() {
        // Monitor eval usage for potential vulnerabilities
        const originalEval = window.eval;
        window.eval = function(code) {
            console.log(`[Eval] Called with: ${this.truncate(code)}`);
            
            this.domXssVulnerabilities.push({
                timestamp: new Date().toISOString(),
                code: this.truncate(code),
                vulnerability: 'eval() usage detected'
            });
            
            console.warn('[VULNERABILITY] eval() usage detected');
            
            return originalEval.call(this, code);
        }.bind(this);
        
        // Monitor new Function as alternative to eval
        const originalFunction = Function;
        window.Function = function() {
            console.log(`[Function] new Function constructor called`);
            
            this.domXssVulnerabilities.push({
                timestamp: new Date().toISOString(),
                args: Array.from(arguments).map(arg => this.truncate(String(arg))),
                vulnerability: 'new Function() usage detected'
            });
            
            console.warn('[VULNERABILITY] new Function() usage detected');
            
            return originalFunction.apply(this, arguments);
        }.bind(this);
    }

    checkForDataLeakage(data) {
        const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data);
        
        for (const [type, regex] of Object.entries(this.sensitiveDataPatterns)) {
            if (regex.test(dataStr)) {
                return true;
            }
        }
        
        return false;
    }
    
    scanForSensitiveData(data, source) {
        if (!data) return;
        
        const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
        
        for (const [type, regex] of Object.entries(this.sensitiveDataPatterns)) {
            if (regex.test(dataStr)) {
                console.warn(`[SENSITIVE DATA] Found ${type} in ${source}`);
                
                // Highlight for AJAX Spider detection
                document.dispatchEvent(new CustomEvent("sensitiveDataDetected", { 
                    detail: { 
                        type: type, 
                        source: source,
                        timestamp: new Date().toISOString()
                    } 
                }));
            }
        }
    }
    
    checkExistingStorage() {
        // Check localStorage
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);
            console.log(`[Existing Storage] localStorage['${key}'] = '${this.truncate(value)}'`);
            this.scanForSensitiveData(value, `localStorage[${key}]`);
        }
        
        // Check sessionStorage
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            const value = sessionStorage.getItem(key);
            console.log(`[Existing Storage] sessionStorage['${key}'] = '${this.truncate(value)}'`);
            this.scanForSensitiveData(value, `sessionStorage[${key}]`);
        }
    }
    
    periodicCheck() {
        console.log('[Monitor] Running periodic security check...');
        
        // Re-check storage for new items
        this.checkExistingStorage();
        
        // Check for new URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        for (const [key, value] of urlParams.entries()) {
            console.log(`[URL] Parameter ${key} = ${value}`);
            this.scanForSensitiveData(value, `URLParam[${key}]`);
        }
        
        // Generate security report
        const report = this.generateSecurityReport();
        console.log('[Monitor] Security Report:', report);
        
        // For AJAX spider detection: create a hidden element with the report summary
        let reportElement = document.getElementById('security-monitor-report');
        if (!reportElement) {
            reportElement = document.createElement('div');
            reportElement.id = 'security-monitor-report';
            reportElement.style.display = 'none';
            document.body.appendChild(reportElement);
        }
        
        reportElement.textContent = JSON.stringify({
            timestamp: new Date().toISOString(),
            vulnerabilities: {
                domXss: this.domXssVulnerabilities.length,
                postMessage: this.postMessageVulnerabilities.length,
                scriptInjection: this.scriptInjectionVulnerabilities.length,
                urlParameter: this.urlParameterVulnerabilities.length
            },
            events: this.detectedEvents.length,
            sensitiveDataDetected: this.detectedEvents.filter(e => e.hasDataLeakage).length
        });
    }
    
    generateSecurityReport() {
        return {
            timestamp: new Date().toISOString(),
            vulnerabilitiesDetected: {
                domXss: this.domXssVulnerabilities,
                postMessage: this.postMessageVulnerabilities,
                scriptInjection: this.scriptInjectionVulnerabilities,
                urlParameter: this.urlParameterVulnerabilities
            },
            events: this.detectedEvents,
            sensitiveDataDetected: this.detectedEvents.filter(e => e.hasDataLeakage)
        };
    }
    
    displayMonitorStatus() {
        // Create status indicator
        const statusIndicator = document.createElement('div');
        statusIndicator.style.position = 'fixed';
        statusIndicator.style.bottom = '10px';
        statusIndicator.style.right = '10px';
        statusIndicator.style.backgroundColor = 'rgba(0, 128, 0, 0.7)';
        statusIndicator.style.color = 'white';
        statusIndicator.style.padding = '5px 10px';
        statusIndicator.style.borderRadius = '3px';
        statusIndicator.style.fontSize = '12px';
        statusIndicator.style.zIndex = '9999';
        statusIndicator.textContent = 'DOM Security Monitor: Active';
        
        document.body.appendChild(statusIndicator);
    }
    
    truncate(str, maxLength = 100) {
        if (!str) return '';
        str = String(str);
        return str.length > maxLength ? str.substring(0, maxLength) + '...' : str;
    }
}

// Create this as a global function that can be called from the console
function startDOMSecurityMonitoring() {
    window.securityMonitor = new DOMSecurityMonitor();
    window.securityMonitor.startMonitoring();
    console.log("DOM Security Monitor initialized. Call window.securityMonitor.generateReport() for results.");
}

// Function to be used in the lab for Challenge 4
function generateSecurityReport() {
    if (window.securityMonitor) {
        window.securityMonitor.generateReport();
    } else {
        console.log("Security monitor not initialized. Run startDOMSecurityMonitoring() first.");
    }
}
