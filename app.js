// Global app state
const appState = {
    // Store data for DOM XSS vulnerabilities
    newsletterSubscribers: [],
    searchHistory: [],
    productReviews: [],
    contactMessages: [],
    visitedPages: [],    products: [
        {
            id: 1,
            name: "Premium Juice Maker",
            description: "Professional quality juice extractor with stainless steel design.",
            price: 199.99,
            image: "images/juice-maker.png"
        },
        {
            id: 2,
            name: "Organic Apple Juice",
            description: "100% organic apple juice with no added sugars or preservatives.",
            price: 4.99,
            image: "images/apple-juice.png"
        },
        {
            id: 3,
            name: "Fresh Orange Juice",
            description: "Freshly squeezed orange juice, rich in Vitamin C.",
            price: 3.99,
            image: "images/orange-juice.png"
        },
        {
            id: 4,
            name: "Berry Mix Smoothie",
            description: "A delicious blend of berries, perfect for breakfast.",
            price: 5.99,
            image: "images/berry-smoothie.png"
        },
        {
            id: 5,
            name: "Green Detox Juice",
            description: "Healthy green juice with spinach, apple, and ginger.",
            price: 6.99,
            image: "images/green-juice.png"
        }
    ],
    cart: [],
    user: null,
    comments: [
        {
            id: 1,
            productId: 1,
            author: "John Doe",
            text: "Great product, highly recommended!",
            date: "2023-05-15"
        },
        {
            id: 2,
            productId: 2,
            author: "Jane Smith",
            text: "The apple juice tastes amazing and fresh.",
            date: "2023-05-20"
        }
    ],
    currentPage: "home",
    searchQuery: "",
    userFeedback: []
};

// DOM Elements
const elements = {
    mainContent: document.getElementById("main-content"),
    searchInput: document.getElementById("search-input"),
    searchButton: document.getElementById("search-button"),
    cartIcon: document.getElementById("cart-icon"),
    cartCount: document.getElementById("cart-count"),
    themeToggleButton: document.getElementById("theme-toggle"),
    showNewsletterLink: document.getElementById("show-newsletter"),
    showQuickSearchLink: document.getElementById("show-quick-search"),
    newsletterModal: document.getElementById("newsletter-modal"),
    closeNewsletter: document.getElementById("close-newsletter"),
    submitNewsletter: document.getElementById("submit-newsletter"),
    newsletterMessage: document.getElementById("newsletter-message"),
    quickSearchModal: document.getElementById("quick-search-modal"),
    closeQuickSearch: document.getElementById("close-quick-search"),
    quickSearchInput: document.getElementById("quick-search-input"),
    quickSearchButton: document.getElementById("quick-search-button"),
    quickSearchResults: document.getElementById("quick-search-results"),
    productReviewModal: document.getElementById("product-review-modal"),
    closeReview: document.getElementById("close-review"),
    submitReview: document.getElementById("submit-review"),
    reviewResult: document.getElementById("review-result"),
    contactModal: document.getElementById("contact-modal"),
    closeContact: document.getElementById("close-contact"),
    submitContact: document.getElementById("submit-contact"),
    contactResult: document.getElementById("contact-result"),
    productDetailModal: document.getElementById("product-detail-modal"),
    closeProductDetail: document.getElementById("close-product-detail"),
    productDetailContent: document.getElementById("product-detail-content"),
    cartModal: document.getElementById("cart-modal"),
    closeCart: document.getElementById("close-cart"),
    cartItemsContainer: document.getElementById("cart-items-container"),
    cartTotal: document.getElementById("cart-total"),
    checkoutButton: document.getElementById("checkout-button"),
    checkoutModal: document.getElementById("checkout-modal"),
    closeCheckout: document.getElementById("close-checkout"),
    checkoutForm: document.getElementById("checkout-form"),
    orderConfirmation: document.getElementById("order-confirmation"),
    closeConfirmation: document.getElementById("close-confirmation"),
    orderDetails: document.getElementById("order-details"),
    continueShopping: document.getElementById("continue-shopping")
};

// Initialize the application
function initApp() {
    renderProducts();
    setupEventListeners();
    
    // Check for previously stored data
    loadFromStorage();
    
    // Process hash fragments (VULNERABLE to DOM XSS)
    processHashFragment();
    
    // Process name parameter with hash (VULNERABLE to DOM XSS)
    processNameParamWithHash();
    
    // Set up hash change listener for continuous monitoring
    window.addEventListener('hashchange', function() {
        console.log('Hash changed, processing again');
        processHashFragment();
        processNameParamWithHash();
    });
    
    // Log application initialized for AJAX spider detection
    console.log("Globomantics SPA initialized");
    
    // Update cart count display
    updateCartCount();
    
    // Handle hash fragment changes for dynamic DOM XSS testing
    window.addEventListener('hashchange', function() {
        console.log('Hash changed, reprocessing...');
        processHashFragment();
    });
}

// VULNERABILITY: Process URL hash fragments without sanitization
function processHashFragment() {
    const hash = window.location.hash.substring(1); // Remove the # symbol
    
    // Get URL parameters to check for name parameter
    const urlParams = new URLSearchParams(window.location.search);
    const nameParam = urlParams.get('name');
    
    console.log('Processing hash:', hash, 'Name param:', nameParam);
    
    if (hash) {
        // DIRECT VULNERABILITY: Process raw hash value without key-value requirement
        // This is INTENTIONALLY vulnerable to inject the hash directly
        const rawHashDiv = document.createElement('div');
        rawHashDiv.className = 'raw-hash-injection';
        
        // Directly insert hash content as HTML without sanitization - SEVERE VULNERABILITY
        rawHashDiv.innerHTML = decodeURIComponent(hash);
        
        // Force immediate insertion into DOM
        document.body.appendChild(rawHashDiv);
        console.log('Raw hash injection processed:', hash);
        
        // Split hash parameters - format: #key1=value1&key2=value2
        const hashParams = {};
        hash.split('&').forEach(param => {
            const [key, value] = param.split('=');
            if (key && value) {
                hashParams[key] = decodeURIComponent(value);
            }
        });
        
        // VULNERABILITY: Display debug information if 'debug' parameter is present
        if (hashParams.debug) {
            const debugDiv = document.createElement('div');
            debugDiv.className = 'debug-panel';
            
            // SEVERE VULNERABILITY: Eval used with user input
            try {
                const debugResult = eval(hashParams.debug);
                debugDiv.innerHTML = `
                    <h3>Debug Information</h3>
                    <pre>${JSON.stringify(debugResult, null, 2)}</pre>
                `;
            } catch (e) {
                debugDiv.innerHTML = `
                    <h3>Debug Information</h3>
                    <p>Error: ${e.message}</p>
                `;
            }
            
            document.body.appendChild(debugDiv);
        }
        
        // VULNERABILITY: Custom theme via hash parameter
        if (hashParams.theme) {
            applyCustomTheme(hashParams.theme);
        }
        
        // VULNERABILITY: Display welcome message directly from hash
        if (hashParams.welcome) {
            const welcomeDiv = document.createElement('div');
            welcomeDiv.className = 'welcome-banner';
            welcomeDiv.innerHTML = hashParams.welcome;
            
            document.getElementById('main-content').prepend(welcomeDiv);
        }
    }
}

// VULNERABILITY: Apply custom theme without validation
function applyCustomTheme(themeCSS) {
    // Create or update custom style element
    let customStyle = document.getElementById('custom-theme-style');
    
    if (!customStyle) {
        customStyle = document.createElement('style');
        customStyle.id = 'custom-theme-style';
        document.head.appendChild(customStyle);
    }
    
    // VULNERABILITY: CSS injection possible here
    customStyle.textContent = decodeURIComponent(themeCSS);
    
    // Store theme preference (preserves the vulnerability)
    localStorage.setItem('userTheme', themeCSS);
}

// Add product event listeners
function addProductEventListeners() {
    // Apply custom layout if specified in URL (VULNERABILITY)
    applyLayoutFromUrl();

    const productCards = document.querySelectorAll('.product-card');
    productCards.forEach(card => {
        // Handle clicks on the card itself (except add-to-cart button)
        card.addEventListener('click', function(event) {
            if (!event.target.classList.contains('add-to-cart')) {
                showProductDetail(parseInt(card.dataset.id));
            }
        });
        
        // Add specific event listener for the add-to-cart button
        const addToCartBtn = card.querySelector('.add-to-cart');
        if (addToCartBtn) {
            addToCartBtn.addEventListener('click', function(event) {
                addToCart(parseInt(card.dataset.id));
                event.stopPropagation();
            });
        }
    });
    
    // Add event listeners to new action buttons
    const showReviewButton = document.getElementById("show-product-review");
    const showContactButton = document.getElementById("show-contact-form");
    
    if (showReviewButton) {
        showReviewButton.addEventListener('click', () => {
            elements.productReviewModal.style.display = "block";
        });
    }
    
    if (showContactButton) {
        showContactButton.addEventListener('click', () => {
            elements.contactModal.style.display = "block";
        });
    }
    
    // Add event listener to feedback form (VULNERABLE to DOM XSS)
    const feedbackButton = document.getElementById("submit-feedback");
    if (feedbackButton) {
        feedbackButton.addEventListener("click", () => {
            const feedbackText = document.getElementById("feedback-text").value;
            
            // Store feedback with sensitive information in sessionStorage
            const feedback = {
                text: feedbackText,
                timestamp: new Date().toISOString(),
                user: appState.user ? appState.user.email : "anonymous",
                userAgent: navigator.userAgent,
                page: window.location.href
            };
            
            appState.userFeedback.push(feedback);
            sessionStorage.setItem("userFeedback", JSON.stringify(appState.userFeedback));
            
            // VULNERABILITY: Direct insertion of user input into DOM (DOM XSS)
            const userFeedbackSection = document.getElementById("user-feedback");
            userFeedbackSection.innerHTML += `
                <div class="comment">
                    <p class="comment-author">${appState.user ? appState.user.email : "Anonymous"}</p>
                    <p>${feedbackText}</p>
                    <p class="comment-date">${new Date().toLocaleDateString()}</p>
                </div>
            `;
            
            document.getElementById("feedback-text").value = "";
            
            // Custom event for monitoring (challenge 4)
            const feedbackEvent = new CustomEvent("userFeedback", { 
                detail: feedback 
            });
            document.dispatchEvent(feedbackEvent);
        });
    }
}

// VULNERABILITY: Apply custom layout configuration from URL parameters
function applyLayoutFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    
    // Look for layout parameters
    if (urlParams.has('layout_css')) {
        const layoutCSS = urlParams.get('layout_css');
        
        // VULNERABILITY: Create and inject custom styles without validation
        const customLayoutStyle = document.createElement('style');
        customLayoutStyle.id = 'custom-layout-style';
        
        // Direct injection of user-controlled CSS
        customLayoutStyle.textContent = decodeURIComponent(layoutCSS);
        document.head.appendChild(customLayoutStyle);
        
        // Store the custom layout for persistent vulnerability
        localStorage.setItem('userLayoutPreference', layoutCSS);
    } else if (localStorage.getItem('userLayoutPreference')) {
        // Apply previously stored layout (persistent vulnerability)
        const storedLayout = localStorage.getItem('userLayoutPreference');
        const customLayoutStyle = document.createElement('style');
        customLayoutStyle.id = 'custom-layout-style';
        
        // Direct injection of previously stored CSS
        customLayoutStyle.textContent = decodeURIComponent(storedLayout);
        document.head.appendChild(customLayoutStyle);
    }
}

// Handle search functionality (VULNERABLE to DOM XSS)
function handleSearch() {
    const query = elements.searchInput.value.trim();
    
    // Store search in history for VULNERABILITY demonstration
    appState.searchHistory.push({
        query: query,
        timestamp: new Date().toISOString()
    });
    
    // Store search history in localStorage (VULNERABILITY)
    localStorage.setItem('searchHistory', JSON.stringify(appState.searchHistory));
    
    // Trigger custom event for monitoring
    document.dispatchEvent(new CustomEvent("userSearch", { 
        detail: { query: query, timestamp: new Date().toISOString() } 
    }));
    
    // VULNERABILITY: Write dynamic content using document.write
    if (query.includes('promo') || query.includes('coupon')) {
        const promoCode = getParameterByName('code') || 'WELCOME10';
        document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Special Promotion</title>
                <link rel="stylesheet" href="styles.css">
            </head>
            <body>
                <div class="promo-page">
                    <h1>Special Promotion Found!</h1>
                    <p>You searched for a promotion. Here is your special offer:</p>
                    <div class="promo-code">${promoCode}</div>
                    <p>Enter this code at checkout for a discount!</p>
                    <button onclick="window.location.href='/'">Return to Homepage</button>
                    
                    <!-- VULNERABILITY: Displays the full query without sanitization -->
                    <div class="search-details">
                        <p>You searched for: ${query}</p>
                    </div>
                </div>
                <script src="app.js"></script>
            </body>
            </html>
        `);
        return; // Stop execution after document.write
    }
    
    // Normal search functionality
    const results = appState.products.filter(product => 
        product.name.toLowerCase().includes(query.toLowerCase()) || 
        product.description.toLowerCase().includes(query.toLowerCase())
    );
    
    renderSearchResults(results, query);
}

// Helper function to get URL parameters (needed for document.write vulnerability)
function getParameterByName(name) {
    const url = window.location.href;
    name = name.replace(/[\[\]]/g, '\\$&');
    const regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
    const results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

// Helper function to create product card HTML
function createProductCard(product) {
    return `
        <div class="product-card" data-id="${product.id}">
            <img src="${product.image}" alt="${product.name}">
            <h3>${product.name}</h3>
            <p>${product.description}</p>
            <p class="product-price">$${product.price.toFixed(2)}</p>
            <button class="add-to-cart" data-id="${product.id}">Add to Cart</button>
        </div>
    `;
}

// Render all products on the home page
function renderProducts() {
    // First, check for dynamic script loading parameters (VULNERABILITY)
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('load_script')) {
        loadExternalScript(urlParams.get('load_script'));
    }
    
    if (urlParams.has('callback')) {
        executeCallback(urlParams.get('callback'));
    }    // Get URL parameters (vulnerable to XSS)
    const showMessage = urlParams.get('message');
    const userName = urlParams.get('name');
      // VULNERABILITY: If name parameter exists, it forces hash processing again
    if (userName) {
        setTimeout(() => {
            processHashFragment(); // Reprocess hash when name parameter exists
            console.log('Hash reprocessed due to name parameter:', userName);
        }, 200);
    }
    
    elements.mainContent.innerHTML = `
        <h2>Our Products</h2>
        
        ${userName ? `
        <!-- VULNERABILITY: Direct insertion of name parameter (DOM XSS) -->
        <div class="user-greeting">
            Welcome, ${userName}!
        </div>
        ` : ''}
        
        ${showMessage ? `
        <!-- VULNERABILITY: Direct insertion of URL parameter (DOM XSS) -->
        <div class="notification-message">
            ${showMessage}
        </div>
        ` : ''}

        <div class="action-buttons">
            <button id="show-product-review" class="action-button">Write a Review</button>
            <button id="show-contact-form" class="action-button">Contact Us</button>
        </div>
        
        <div class="product-grid">
            ${appState.products.map(product => createProductCard(product)).join('')}
        </div>
        
        <div id="user-feedback">
            <h3>Leave Your Feedback</h3>
            <div class="comment-form">
                <textarea id="feedback-text" placeholder="Share your thoughts about our products..."></textarea>
                <button id="submit-feedback">Submit Feedback</button>
            </div>
        </div>
    `;
    
    addProductEventListeners();
}

// VULNERABILITY: Load external scripts without validation
function loadExternalScript(url) {
    const script = document.createElement('script');
    script.src = url;
    document.head.appendChild(script);
    console.log(`Loaded external script from: ${url}`);
}

// VULNERABILITY: Execute arbitrary callback functions
function executeCallback(callbackName) {
    try {
        // This is extremely dangerous - allows for remote code execution
        window[callbackName] && window[callbackName]();
    } catch (e) {
        console.error(`Error executing callback: ${e}`);
    }
}

// Function to render search results (with DOM XSS vulnerability)
function renderSearchResults(results, query) {
    // VULNERABILITY: Store search query in document title (reflected DOM XSS)
    document.title = `Search results for: ${query} - Globomantics`;
    
    let resultsHTML = `
        <h2>Search Results for "${query}"</h2>
        <p>Found ${results.length} items</p>
        <button class="back-button" onclick="renderProducts()">Back to Products</button>
    `;
    
    if (results.length === 0) {
        resultsHTML += '<p>No products found. Try a different search term.</p>';
    } else {
        resultsHTML += `
            <div class="product-grid">
                ${results.map(product => createProductCard(product)).join('')}
            </div>
        `;
    }
    
    elements.mainContent.innerHTML = resultsHTML;
    
    // Add event listeners to the newly created product cards
    const productCards = document.querySelectorAll('.product-card');
    productCards.forEach(card => {
        const productId = parseInt(card.dataset.id);
        
        card.addEventListener('click', function(event) {
            if (event.target.classList.contains('add-to-cart')) {
                addToCart(productId);
                event.stopPropagation();
            } else {
                showProductDetail(productId);
            }
        });
    });
}

// Function to render a product detail page (with DOM XSS vulnerabilities)
function showProductDetail(productId) {
    const product = appState.products.find(p => p.id === productId);
    
    if (!product) {
        console.error("Product not found");
        return;
    }
    
    // VULNERABILITY: Store visited product in history for tracking
    appState.visitedPages.push({
        productId: productId,
        timestamp: new Date().toISOString()
    });
    localStorage.setItem('visitedPages', JSON.stringify(appState.visitedPages));
    
    // Display product details in a modal
    const comments = appState.comments.filter(c => c.productId === productId);
    
    elements.productDetailContent.innerHTML = `
        <div class="product-detail">
            <h2>${product.name}</h2>
            <img src="${product.image}" alt="${product.name}" class="product-detail-image">
            <p class="product-description">${product.description}</p>
            <p class="product-price">$${product.price.toFixed(2)}</p>
            <button class="add-to-cart-detail" data-id="${product.id}">Add to Cart</button>
            
            <div class="product-reviews">
                <h3>Customer Reviews</h3>
                ${comments.length > 0 ? 
                    comments.map(comment => `
                        <div class="comment">
                            <p class="comment-author">${comment.author}</p>
                            <p>${comment.text}</p>
                            <p class="comment-date">${comment.date}</p>
                        </div>
                    `).join('') : 
                    '<p>No reviews yet. Be the first to review this product!</p>'
                }
            </div>
        </div>
    `;
    
    // Add event listener to the Add to Cart button
    const addToCartBtn = elements.productDetailContent.querySelector('.add-to-cart-detail');
    addToCartBtn.addEventListener('click', () => {
        addToCart(productId);
    });
    
    // Show the modal
    elements.productDetailModal.style.display = "block";
}

// Function to add a product to the cart (with localStorage vulnerability)
function addToCart(productId) {
    const product = appState.products.find(p => p.id === productId);
    
    if (!product) {
        console.error("Product not found");
        return;
    }
    
    // Check if product is already in cart
    const cartItem = appState.cart.find(item => item.id === productId);
    
    if (cartItem) {
        cartItem.quantity += 1;
    } else {
        appState.cart.push({
            id: product.id,
            name: product.name,
            price: product.price,
            image: product.image,
            quantity: 1
        });
    }
    
    // VULNERABILITY: Store cart in localStorage (sensitive information)
    localStorage.setItem('cart', JSON.stringify(appState.cart));
    
    // Update cart count display
    updateCartCount();
    
    // Show visual feedback
    showCartNotification(product.name);
}

// Function to load data from storage (persistence of vulnerabilities)
function loadFromStorage() {
    // Load cart data
    const cartData = localStorage.getItem('cart');
    if (cartData) {
        try {
            appState.cart = JSON.parse(cartData);
        } catch (e) {
            console.error("Error loading cart data:", e);
        }
    }
    
    // Load search history
    const searchHistory = localStorage.getItem('searchHistory');
    if (searchHistory) {
        try {
            appState.searchHistory = JSON.parse(searchHistory);
        } catch (e) {
            console.error("Error loading search history:", e);
        }
    }
    
    // Load newsletter subscribers
    const subscribers = localStorage.getItem('newsletterSubscribers');
    if (subscribers) {
        try {
            appState.newsletterSubscribers = JSON.parse(subscribers);
        } catch (e) {
            console.error("Error loading newsletter subscribers:", e);
        }
    }
}

// Update cart item count display
function updateCartCount() {
    const totalItems = appState.cart.reduce((total, item) => total + item.quantity, 0);
    elements.cartCount.textContent = totalItems;
}

// Function to render cart items
function renderCartItems() {
    if (appState.cart.length === 0) {
        elements.cartItemsContainer.innerHTML = '<p>Your cart is empty.</p>';
        elements.cartTotal.textContent = '0.00';
        return;
    }
    
    let total = 0;
    let cartHTML = '<div class="cart-items">';
    
    appState.cart.forEach(item => {
        const itemTotal = item.price * item.quantity;
        total += itemTotal;
        
        cartHTML += `
            <div class="cart-item">
                <img src="${item.image}" alt="${item.name}" class="cart-item-image">
                <div class="cart-item-details">
                    <h4>${item.name}</h4>
                    <p>$${item.price.toFixed(2)} x ${item.quantity}</p>
                </div>
                <div class="cart-item-actions">
                    <button class="cart-item-remove" data-id="${item.id}">Remove</button>
                </div>
            </div>
        `;
    });
    
    cartHTML += '</div>';
    elements.cartItemsContainer.innerHTML = cartHTML;
    elements.cartTotal.textContent = total.toFixed(2);
    
    // Add event listeners to remove buttons
    const removeButtons = document.querySelectorAll('.cart-item-remove');
    removeButtons.forEach(button => {
        button.addEventListener('click', () => {
            removeFromCart(parseInt(button.dataset.id));
        });
    });
}

// Function to remove items from cart
function removeFromCart(productId) {
    appState.cart = appState.cart.filter(item => item.id !== productId);
    localStorage.setItem('cart', JSON.stringify(appState.cart));
    
    renderCartItems();
    updateCartCount();
}

// Show cart notification
function showCartNotification(productName) {
    const notification = document.createElement('div');
    notification.className = 'cart-notification';
    notification.textContent = `${productName} added to cart!`;
    
    document.body.appendChild(notification);
    
    // Remove notification after animation
    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 500);
    }, 2000);
}

// Toggle between light and dark theme
function toggleTheme() {
    document.body.classList.toggle('dark-theme');
    
    // VULNERABILITY: Store theme preference in localStorage
    const isDarkTheme = document.body.classList.contains('dark-theme');
    localStorage.setItem('darkTheme', isDarkTheme);
}

// Handle newsletter subscription (with DOM XSS vulnerability)
function handleNewsletterSubscription() {
    const email = document.getElementById('newsletter-email').value.trim();
    const name = document.getElementById('newsletter-name').value.trim();
    const interests = document.getElementById('newsletter-interests').value.trim();
    
    if (!email || !name) {
        elements.newsletterMessage.innerHTML = '<p class="error">Please enter your name and email.</p>';
        return;
    }
    
    // Store subscriber data (VULNERABILITY: PII stored in localStorage)
    const subscriber = {
        email: email,
        name: name,
        interests: interests,
        date: new Date().toISOString()
    };
    
    appState.newsletterSubscribers.push(subscriber);
    localStorage.setItem('newsletterSubscribers', JSON.stringify(appState.newsletterSubscribers));
    
    // VULNERABILITY: Reflected user input
    elements.newsletterMessage.innerHTML = `
        <p class="success">
            Thank you, ${name}! You have been subscribed to our newsletter.
            <br>
            <!-- VULNERABILITY: Displaying user input without sanitization -->
            We'll send updates about: ${interests || "all products"}
        </p>
    `;
    
    // Reset form
    document.getElementById('newsletter-email').value = '';
    document.getElementById('newsletter-name').value = '';
    document.getElementById('newsletter-interests').value = '';
    
    // Trigger custom event for monitoring
    document.dispatchEvent(new CustomEvent("newsletterSignup", { 
        detail: { email: email, name: name } 
    }));
}

// Handle quick search (with DOM XSS vulnerability)
function handleQuickSearch() {
    const query = elements.quickSearchInput.value.trim();
    
    if (!query) {
        elements.quickSearchResults.innerHTML = '<p>Please enter a search term.</p>';
        return;
    }
    
    // Store search in history for VULNERABILITY demonstration
    appState.searchHistory.push({
        query: query,
        timestamp: new Date().toISOString()
    });
    
    // Store search history in localStorage (VULNERABILITY)
    localStorage.setItem('searchHistory', JSON.stringify(appState.searchHistory));
    
    // Search products
    const results = appState.products.filter(product => 
        product.name.toLowerCase().includes(query.toLowerCase()) || 
        product.description.toLowerCase().includes(query.toLowerCase())
    );
    
    // VULNERABILITY: Direct insertion of user input
    if (results.length === 0) {
        elements.quickSearchResults.innerHTML = `
            <p>No results found for "${query}".</p>
            <p class="search-suggestion">
                Try searching for: juice, smoothie, or detox
            </p>
        `;
    } else {
        let resultsHTML = `
            <p>Found ${results.length} results for "${query}":</p>
            <ul class="quick-search-list">
        `;
        
        results.forEach(product => {
            resultsHTML += `
                <li>
                    <img src="${product.image}" alt="${product.name}" class="search-result-image">
                    <div class="search-result-details">
                        <h4>${product.name}</h4>
                        <p class="search-result-price">$${product.price.toFixed(2)}</p>
                    </div>
                </li>
            `;
        });
        
        resultsHTML += '</ul>';
        elements.quickSearchResults.innerHTML = resultsHTML;
    }
    
    // Trigger custom event for monitoring
    document.dispatchEvent(new CustomEvent("userSearch", { 
        detail: { query: query, timestamp: new Date().toISOString() } 
    }));
}

// Handle product review submission (with DOM XSS vulnerability)
function handleProductReview() {
    const name = document.getElementById('review-name').value.trim();
    const rating = document.getElementById('review-rating').value;
    const reviewText = document.getElementById('review-text').value.trim();
    const website = document.getElementById('review-website').value.trim();
    
    if (!name || !reviewText) {
        elements.reviewResult.innerHTML = '<p class="error">Please enter your name and review.</p>';
        return;
    }
    
    // Store review (VULNERABILITY: User input stored and displayed)
    const review = {
        name: name,
        rating: rating,
        text: reviewText,
        website: website,
        date: new Date().toISOString()
    };
    
    // Add to product reviews (stored in appState and sessionStorage)
    appState.productReviews.push(review);
    sessionStorage.setItem('productReviews', JSON.stringify(appState.productReviews));
    
    // VULNERABILITY: Direct insertion of user input including website link
    elements.reviewResult.innerHTML = `
        <p class="success">Thank you for your review!</p>
        <div class="submitted-review">
            <p class="reviewer-name">
                ${review.website ? `<a href="${review.website}" target="_blank">${name}</a>` : name}
            </p>
            <div class="star-rating">Rating: ${rating}/5</div>
            <p>${reviewText}</p>
            <p class="review-date">${new Date().toLocaleDateString()}</p>
        </div>
    `;
    
    // Reset form fields
    document.getElementById('review-name').value = '';
    document.getElementById('review-rating').value = '5';
    document.getElementById('review-text').value = '';
    document.getElementById('review-website').value = '';
    
    // Trigger custom event for monitoring
    document.dispatchEvent(new CustomEvent("productReview", { 
        detail: { name: name, rating: rating } 
    }));
}

// Handle contact form submission (with DOM XSS vulnerability)
function handleContactSubmission() {
    const name = document.getElementById('contact-name').value.trim();
    const email = document.getElementById('contact-email').value.trim();
    const subject = document.getElementById('contact-subject').value.trim();
    const message = document.getElementById('contact-message').value.trim();
    
    if (!name || !email || !message) {
        elements.contactResult.innerHTML = '<p class="error">Please fill all required fields.</p>';
        return;
    }
    
    // Store contact message (VULNERABILITY: PII stored in sessionStorage)
    const contactMessage = {
        name: name,
        email: email,
        subject: subject,
        message: message,
        date: new Date().toISOString(),
        userAgent: navigator.userAgent
    };
    
    appState.contactMessages.push(contactMessage);
    sessionStorage.setItem('contactMessages', JSON.stringify(appState.contactMessages));
    
    // VULNERABILITY: Direct insertion of user input
    elements.contactResult.innerHTML = `
        <p class="success">Thank you for your message, ${name}!</p>
        <p>We've received your inquiry about "${subject || 'our products'}" and will get back to you soon at ${email}.</p>
    `;
    
    // Reset form
    document.getElementById('contact-name').value = '';
    document.getElementById('contact-email').value = '';
    document.getElementById('contact-subject').value = '';
    document.getElementById('contact-message').value = '';
    
    // Trigger custom event for monitoring
    document.dispatchEvent(new CustomEvent("contactSubmission", { 
        detail: { name: name, email: email, subject: subject } 
    }));
}

// VULNERABILITY: Handle checkout with insecure storage of sensitive data
function handleCheckout(event) {
    event.preventDefault();
    
    // Get form values
    const fullName = document.getElementById('full-name').value;
    const billingAddress = document.getElementById('billing-address').value;
    const creditCard = document.getElementById('credit-card').value;
    const expiry = document.getElementById('expiry').value;
    const cvv = document.getElementById('cvv').value;
    
    // Calculate order total
    const orderTotal = appState.cart.reduce((total, item) => {
        return total + (item.price * item.quantity);
    }, 0);
    
    // Create order object with sensitive information
    const order = {
        orderId: generateOrderId(),
        fullName: fullName,
        billingAddress: billingAddress,
        creditCard: creditCard, // VULNERABILITY: Storing full credit card number
        expiry: expiry,
        cvv: cvv, // VULNERABILITY: Storing CVV
        items: appState.cart,
        orderTotal: orderTotal,
        orderDate: new Date().toISOString()
    };
    
    // VULNERABILITY: Store sensitive order data in localStorage and sessionStorage
    localStorage.setItem('lastOrderDetails', JSON.stringify(order));
    sessionStorage.setItem('lastOrder', JSON.stringify(order));
    
    // VULNERABILITY: Store credit card for "convenience"
    localStorage.setItem('savedCreditCard', JSON.stringify({
        number: creditCard,
        expiry: expiry,
        cvv: cvv
    }));
    
    // Clear cart
    appState.cart = [];
    localStorage.setItem('cart', JSON.stringify(appState.cart));
    updateCartCount();
    
    // Show order confirmation
    displayOrderConfirmation(order);
    
    // Close checkout modal
    elements.checkoutModal.style.display = "none";
    elements.orderConfirmation.style.display = "block";
    
    // Reset form
    elements.checkoutForm.reset();
    
    // Trigger custom event for monitoring (for Challenge 4)
    document.dispatchEvent(new CustomEvent("orderPlaced", { 
        detail: { 
            orderId: order.orderId,
            total: order.orderTotal,
            items: order.items.length,
            payment: "Credit Card"
        } 
    }));
}

// Helper function for order confirmation
function displayOrderConfirmation(order) {
    // VULNERABILITY: Display sensitive information in confirmation
    elements.orderDetails.innerHTML = `
        <div class="order-success">
            <p>Thank you for your order, ${order.fullName}!</p>
            <p>Order #${order.orderId}</p>
            <p>Total: $${order.orderTotal.toFixed(2)}</p>
            
            <!-- VULNERABILITY: Displays partial credit card info -->
            <p>Paid with: Credit card ending in ${order.creditCard.slice(-4)}</p>
            
            <div class="order-items">
                <h3>Order Items:</h3>
                <ul>
                    ${order.items.map(item => `
                        <li>${item.name} x ${item.quantity} - $${(item.price * item.quantity).toFixed(2)}</li>
                    `).join('')}
                </ul>
            </div>
            
            <!-- VULNERABILITY: Display with potential HTML injection via order details -->
            <div class="shipping-info">
                <h3>Shipping Information:</h3>
                <p>${order.billingAddress}</p>
            </div>
        </div>
    `;
}

// Generate random order ID
function generateOrderId() {
    return 'ORD-' + Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
}

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    elements.searchButton.addEventListener("click", handleSearch);
    elements.searchInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            handleSearch();
        }
    });
    
    // Add window event listener to close modals when clicking outside
    window.addEventListener('click', (event) => {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    });
    
    // Theme Toggle
    elements.themeToggleButton.addEventListener("click", toggleTheme);
    
    // Newsletter modal
    elements.showNewsletterLink.addEventListener("click", (e) => {
        e.preventDefault();
        elements.newsletterModal.style.display = "block";
    });
    
    elements.closeNewsletter.addEventListener("click", () => {
        elements.newsletterModal.style.display = "none";
    });
    
    elements.submitNewsletter.addEventListener("click", handleNewsletterSubscription);
      // Quick Search modal
    if (elements.showQuickSearchLink) {
        elements.showQuickSearchLink.addEventListener("click", (e) => {
            e.preventDefault();
            elements.quickSearchModal.style.display = "block";
        });
    }
    
    if (elements.closeQuickSearch) {
        elements.closeQuickSearch.addEventListener("click", () => {
            elements.quickSearchModal.style.display = "none";
        });
    }
    
    if (elements.quickSearchButton) {
        elements.quickSearchButton.addEventListener("click", handleQuickSearch);
    }
    
    if (elements.quickSearchInput) {
        elements.quickSearchInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") {
                handleQuickSearch();
            }
        });
    }// Product Review modal
    elements.closeReview.addEventListener("click", function(event) {
        console.log("Close review button clicked");
        elements.productReviewModal.style.display = "none";
        event.stopPropagation(); // Prevent event bubbling
    });
    
    elements.submitReview.addEventListener("click", handleProductReview);
    
    // Contact modal
    elements.closeContact.addEventListener("click", function(event) {
        console.log("Close contact button clicked");
        elements.contactModal.style.display = "none";
        event.stopPropagation(); // Prevent event bubbling
    });
    
    // Product Detail modal
    elements.closeProductDetail.addEventListener("click", () => {
        elements.productDetailModal.style.display = "none";
    });
    
    elements.submitContact.addEventListener("click", handleContactSubmission);
    
    // Cart modal
    elements.cartIcon.addEventListener("click", () => {
        renderCartItems();
        elements.cartModal.style.display = "block";
    });
    
    elements.closeCart.addEventListener("click", () => {
        elements.cartModal.style.display = "none";
    });
    
    // Checkout
    elements.checkoutButton.addEventListener("click", () => {
        elements.cartModal.style.display = "none";
        elements.checkoutModal.style.display = "block";
    });
    
    elements.closeCheckout.addEventListener("click", () => {
        elements.checkoutModal.style.display = "none";
    });
    
    // Handle checkout form submission - VULNERABILITY: Storing sensitive data
    elements.checkoutForm.addEventListener("submit", handleCheckout);
    
    // Handle order confirmation
    elements.closeConfirmation.addEventListener("click", () => {
        elements.orderConfirmation.style.display = "none";
    });
    
    elements.continueShopping.addEventListener("click", () => {
        elements.orderConfirmation.style.display = "none";
        renderProducts();
    });
      // Add a general event handler for all modal close buttons
    document.querySelectorAll('.close').forEach(closeBtn => {
        closeBtn.addEventListener("click", (event) => {
            const modal = closeBtn.closest('.modal');
            if (modal) {
                modal.style.display = "none";
            }
            event.stopPropagation(); // Stop event from bubbling up
        });
    });
}

// VULNERABILITY: Direct XSS from name parameter with hash fragment
function processNameParamWithHash() {
    const urlParams = new URLSearchParams(window.location.search);
    const nameParam = urlParams.get('name');
    const hash = window.location.hash.substring(1);
    
    if (nameParam && hash) {
        console.log(`Processing vulnerable name+hash combination: name=${nameParam}, hash=${hash}`);
        
        // Create a container for the vulnerability
        const vulnContainer = document.createElement('div');
        vulnContainer.className = 'name-hash-vulnerability';
        
        // SEVERE VULNERABILITY: Directly append both name param and hash as HTML
        vulnContainer.innerHTML = `
            <div>User: ${nameParam}</div>
            <div class="hash-content">${decodeURIComponent(hash)}</div>
        `;
        
        // Add to DOM in multiple locations to ensure it works
        document.body.appendChild(vulnContainer);
        
        if (document.getElementById('main-content')) {
            document.getElementById('main-content').prepend(vulnContainer.cloneNode(true));
        }
    }
}

// Initialize the application when the DOM content is loaded
document.addEventListener('DOMContentLoaded', function() {
    initApp();
    // Process hash fragment again after DOM is fully loaded to ensure it works
    setTimeout(() => {
        processHashFragment();
        processNameParamWithHash(); // Add our new vulnerable function
        console.log("Hash fragment and name param processed after DOM content loaded");
    }, 300);
    console.log("Application initialized - DOM content loaded");
});

// Call initApp function immediately to handle the case where the script loads after DOMContentLoaded
initApp();
console.log("Application initialization attempted directly");