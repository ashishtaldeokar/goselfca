document.addEventListener('DOMContentLoaded', () => {
    // Implement copy to clipboard functionality for code blocks
    const copyButtons = document.querySelectorAll('.copy-btn');

    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Find the sibling <pre> element which contains the <code>
            const codeBlock = button.parentElement.querySelector('pre code');
            
            if (codeBlock) {
                const textToCopy = codeBlock.innerText;

                // Use the Clipboard API
                navigator.clipboard.writeText(textToCopy).then(() => {
                    // Visual feedback
                    const originalText = button.innerText;
                    button.innerText = 'Copied!';
                    button.classList.add('copied');

                    // Revert back after 2 seconds
                    setTimeout(() => {
                        button.innerText = originalText;
                        button.classList.remove('copied');
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy text: ', err);
                    button.innerText = 'Error';
                    
                    setTimeout(() => {
                        button.innerText = 'Copy';
                    }, 2000);
                });
            }
        });
    });

    // Add subtle entrance animations to elements as they scroll into view
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Apply animation starting state to cards and feature items
    const animatableElements = document.querySelectorAll('.card, .feature-item, .config-section');
    
    animatableElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease-out, transform 0.6s ease-out';
        observer.observe(el);
    });
});
