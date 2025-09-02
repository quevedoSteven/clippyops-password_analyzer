class MilitaryPasswordAnalyzer {
    constructor() {
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.initializeSecurityProtocols();
    }
    
    setupEventListeners() {
        document.addEventListener('DOMContentLoaded', () => {
            this.initializeComponents();
        });
    }
    
    initializeComponents() {
        this.initializeFormValidation();
        this.setupSecurityIndicators();
        this.initializeAnimations();
    }
    
    initializeFormValidation() {
        const form = document.getElementById('passwordForm');
        if (form) {
            form.addEventListener('submit', (e) => {
                this.validateFormSubmission(e);
            });
        }
    }
    
    validateFormSubmission(event) {
        const password = document.getElementById('password');
        if (password && password.value.length < 4) {
            event.preventDefault();
            this.showSecurityAlert('PASSWORD TOO SHORT - MINIMUM 4 CHARACTERS REQUIRED');
            return false;
        }
        return true;
    }
    
    showSecurityAlert(message) {
        const alert = document.createElement('div');
        alert.className = 'security-alert';
        alert.innerHTML = `
            <div class="alert-header">
                <span class="alert-icon">⚠️</span>
                <span class="alert-title">SECURITY ALERT</span>
            </div>
            <div class="alert-message">${message}</div>
        `;
        
        document.body.appendChild(alert);
        
        setTimeout(() => {
            alert.remove();
        }, 5000);
    }
    
    setupSecurityIndicators() {
        const indicators = document.querySelectorAll('.security-indicator');
        indicators.forEach(indicator => {
            this.animateSecurityIndicator(indicator);
        });
    }
    
    animateSecurityIndicator(indicator) {
        const status = indicator.dataset.status;
        if (status === 'active') {
            indicator.classList.add('pulsing');
        }
    }
    
    initializeAnimations() {
        const cards = document.querySelectorAll('.result-card, .dashboard-card, .feature-card');
        cards.forEach((card, index) => {
            card.style.animationDelay = `${index * 0.1}s`;
        });
    }
    
    generateSecurePassword(length = 16) {
        const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        let password = "";
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return password;
    }
    
    initializeSecurityProtocols() {
        this.setupSessionSecurity();
        this.initializeThreatMonitoring();
    }
    
    setupSessionSecurity() {
        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.setItem('security_session', Date.now().toString());
        }
    }
    
    initializeThreatMonitoring() {
        setInterval(() => {
            this.updateSecurityStatus();
        }, 30000);
    }
    
    updateSecurityStatus() {
        const statusElements = document.querySelectorAll('.security-status');
        statusElements.forEach(element => {
            element.classList.toggle('active');
        });
    }
    
    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password');
        const showPassword = document.getElementById('showPassword');
        if (passwordInput && showPassword) {
            passwordInput.type = showPassword.checked ? 'text' : 'password';
        }
    }
    
    loadSecurityIntelligence() {
        fetch('/api/security-intelligence')
            .then(response => response.json())
            .then(data => {
                this.displaySecurityIntelligence(data);
            })
            .catch(error => {
                console.error('SECURITY INTELLIGENCE ERROR:', error);
            });
    }
    
    displaySecurityIntelligence(data) {
        const container = document.getElementById('intelligenceData');
        if (container) {
            container.innerHTML = '';
            for (const [key, value] of Object.entries(data)) {
                const item = document.createElement('div');
                item.className = 'intelligence-item';
                item.innerHTML = `
                    <div class="intelligence-key">${key.replace('_', ' ').toUpperCase()}</div>
                    <div class="intelligence-value">${value}</div>
                `;
                container.appendChild(item);
            }
        }
    }
}

class AdvancedAnalytics {
    constructor() {
        this.metrics = {};
        this.initializeAnalytics();
    }
    
    initializeAnalytics() {
        this.trackUserBehavior();
        this.setupPerformanceMonitoring();
    }
    
    trackUserBehavior() {
        const elements = document.querySelectorAll('[data-track]');
        elements.forEach(element => {
            element.addEventListener('click', (e) => {
                this.logUserAction(e.target.dataset.track);
            });
        });
    }
    
    logUserAction(action) {
        if (!this.metrics[action]) {
            this.metrics[action] = 0;
        }
        this.metrics[action]++;
        console.log(`USER ACTION: ${action} - COUNT: ${this.metrics[action]}`);
    }
    
    setupPerformanceMonitoring() {
        if ('performance' in window) {
            window.addEventListener('load', () => {
                setTimeout(() => {
                    this.logPerformanceMetrics();
                }, 1000);
            });
        }
    }
    
    logPerformanceMetrics() {
        const perfData = performance.getEntriesByType('navigation')[0];
        if (perfData) {
            console.log(`PAGE LOAD TIME: ${perfData.loadEventEnd - perfData.loadEventStart}ms`);
        }
    }
}

const militaryAnalyzer = new MilitaryPasswordAnalyzer();
const analytics = new AdvancedAnalytics();

function togglePasswordVisibility() {
    militaryAnalyzer.togglePasswordVisibility();
}

function generateSecurePassword() {
    const password = militaryAnalyzer.generateSecurePassword();
    document.getElementById('password').value = password;
}

document.addEventListener('DOMContentLoaded', () => {
    militaryAnalyzer.loadSecurityIntelligence();
});