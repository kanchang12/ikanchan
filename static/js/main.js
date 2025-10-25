// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {

// Mobile Menu Toggle
const mobileMenuBtn = document.getElementById('mobileMenuBtn');
const navLinks = document.querySelector('.nav-links');

if (mobileMenuBtn) {
    mobileMenuBtn.addEventListener('click', () => {
        navLinks.classList.toggle('active');
    });
}

// Close mobile menu when clicking outside
document.addEventListener('click', (e) => {
    if (!e.target.closest('.nav-content')) {
        navLinks.classList.remove('active');
    }
});

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            const offset = 80;
            const targetPosition = target.offsetTop - offset;
            window.scrollTo({
                top: targetPosition,
                behavior: 'smooth'
            });
            navLinks.classList.remove('active');
        }
    });
});

// Analysis Tabs
const tabBtns = document.querySelectorAll('.tab-btn');
const tabPanels = document.querySelectorAll('.tab-panel');

tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.getAttribute('data-tab');
        
        // Remove active class from all tabs and panels
        tabBtns.forEach(b => b.classList.remove('active'));
        tabPanels.forEach(p => p.classList.remove('active'));
        
        // Add active class to clicked tab and corresponding panel
        btn.classList.add('active');
        document.getElementById(`${tabName}-panel`).classList.add('active');
    });
});

// GitHub Analysis Form
const githubForm = document.getElementById('githubForm');
const githubResult = document.getElementById('github-result');
const githubResultContent = document.getElementById('github-result-content');
const githubSubmitBtn = document.getElementById('githubSubmitBtn');

if (githubForm) {
    githubForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const urlInput = document.getElementById('github-url');
        if (!urlInput) {
            console.error('GitHub URL input not found');
            return;
        }
        const url = urlInput.value;
        
        // Show loading state
        githubSubmitBtn.disabled = true;
        githubSubmitBtn.textContent = 'Analyzing...';
        githubResult.style.display = 'none';
        
        try {
            const response = await fetch('/api/analyze-github', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                githubResultContent.textContent = data.analysis;
                githubResult.style.display = 'block';
                githubResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            } else {
                alert(data.error || 'Analysis failed. Please try again.');
            }
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            githubSubmitBtn.disabled = false;
            githubSubmitBtn.textContent = 'Analyze Repository';
        }
    });
}

// Website Analysis Form
const websiteForm = document.getElementById('websiteForm');
const websiteResult = document.getElementById('website-result');
const websiteResultContent = document.getElementById('website-result-content');
const websiteSubmitBtn = document.getElementById('websiteSubmitBtn');

if (websiteForm) {
    websiteForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const urlInput = document.getElementById('website-url');
        if (!urlInput) {
            console.error('Website URL input not found');
            return;
        }
        const url = urlInput.value;
        
        // Show loading state
        websiteSubmitBtn.disabled = true;
        websiteSubmitBtn.textContent = 'Analyzing...';
        websiteResult.style.display = 'none';
        
        try {
            const response = await fetch('/api/analyze-web', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                websiteResultContent.textContent = data.analysis;
                websiteResult.style.display = 'block';
                websiteResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            } else {
                alert(data.error || 'Analysis failed. Please try again.');
            }
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            websiteSubmitBtn.disabled = false;
            websiteSubmitBtn.textContent = 'Analyze Website';
        }
    });
}

// Contact Form
const contactForm = document.getElementById('contactForm');
const contactSuccess = document.getElementById('contactSuccess');
const contactSubmitBtn = document.getElementById('contactSubmitBtn');

if (contactForm) {
    contactForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const nameInput = document.getElementById('name');
        const emailInput = document.getElementById('email');
        const projectTypeInput = document.getElementById('project-type');
        const urlInput = document.getElementById('url');
        const messageInput = document.getElementById('message');
        
        if (!nameInput || !emailInput) {
            console.error('Required contact form fields not found');
            return;
        }
        
        const formData = {
            name: nameInput.value,
            email: emailInput.value,
            project_type: projectTypeInput ? projectTypeInput.value : '',
            url: urlInput ? urlInput.value : '',
            message: messageInput ? messageInput.value : ''
        };
        
        // Show loading state
        contactSubmitBtn.disabled = true;
        contactSubmitBtn.textContent = 'Sending...';
        
        try {
            const response = await fetch('/api/contact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                contactSuccess.style.display = 'flex';
                contactForm.reset();
                setTimeout(() => {
                    contactSuccess.style.display = 'none';
                }, 5000);
            } else {
                alert(data.error || 'Submission failed. Please try again.');
            }
        } catch (error) {
            alert('Error: ' + error.message);
        } finally {
            contactSubmitBtn.disabled = false;
            contactSubmitBtn.textContent = 'Send Message';
        }
    });
}

// Chatbot
const chatbot = document.getElementById('chatbot');
const chatbotToggle = document.getElementById('chatbotToggle');
const chatbotClose = document.getElementById('chatbotClose');
const chatbotForm = document.getElementById('chatbotForm');
const chatbotInput = document.getElementById('chatbotInput');
const chatbotMessages = document.getElementById('chatbotMessages');

let chatHistory = [];
let sessionId = null;

// Toggle chatbot
if (chatbotToggle) {
    chatbotToggle.addEventListener('click', () => {
        chatbot.classList.toggle('active');
        if (chatbot.classList.contains('active')) {
            chatbotInput.focus();
        }
    });
}

if (chatbotClose) {
    chatbotClose.addEventListener('click', () => {
        chatbot.classList.remove('active');
    });
}

// Send message
if (chatbotForm) {
    chatbotForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const message = chatbotInput.value.trim();
        if (!message) return;
        
        // Add user message to UI
        addMessage(message, 'user');
        chatbotInput.value = '';
        
        // Add typing indicator
        const typingIndicator = addTypingIndicator();
        
        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message,
                    history: chatHistory,
                    session_id: sessionId
                })
            });
            
            const data = await response.json();
            
            // Remove typing indicator
            typingIndicator.remove();
            
            if (response.ok) {
                sessionId = data.session_id;
                addMessage(data.response, 'bot');
                
                // Update history
                chatHistory.push({ role: 'user', content: message });
                chatHistory.push({ role: 'assistant', content: data.response });
            } else {
                addMessage('Sorry, I encountered an error. Please try again.', 'bot');
            }
        } catch (error) {
            typingIndicator.remove();
            addMessage('Sorry, I could not connect. Please try again later.', 'bot');
        }
    });
}

function addMessage(text, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `chatbot-message ${type}-message`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = text;
    
    messageDiv.appendChild(contentDiv);
    chatbotMessages.appendChild(messageDiv);
    
    // Scroll to bottom
    chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
    
    return messageDiv;
}

function addTypingIndicator() {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chatbot-message bot-message';
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.innerHTML = '<em>Typing...</em>';
    
    messageDiv.appendChild(contentDiv);
    chatbotMessages.appendChild(messageDiv);
    
    // Scroll to bottom
    chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
    
    return messageDiv;
}

// Scroll animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observe elements for scroll animation
document.querySelectorAll('.service-card, .portfolio-item, .why-item').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
});

// Sticky nav on scroll
let lastScrollTop = 0;
const nav = document.querySelector('.nav');

window.addEventListener('scroll', () => {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    
    if (scrollTop > 100) {
        nav.style.boxShadow = 'var(--shadow-md)';
    } else {
        nav.style.boxShadow = 'var(--shadow-sm)';
    }
    
    lastScrollTop = scrollTop;
});

// Initialize AOS-like animations on load
window.addEventListener('load', () => {
    document.querySelectorAll('.service-card, .portfolio-item, .why-item').forEach((el, index) => {
        setTimeout(() => {
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
        }, index * 100);
    });
});

}); // End DOMContentLoaded