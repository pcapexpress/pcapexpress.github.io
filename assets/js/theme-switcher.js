document.addEventListener('DOMContentLoaded', () => {
    const html = document.documentElement;
    
    // Switch to Stealth
    document.getElementById('btn-stealth').addEventListener('click', () => {
        html.setAttribute('data-theme', 'stealth');
        localStorage.setItem('theme', 'stealth');
    });

    // Switch to Active
    document.getElementById('btn-active').addEventListener('click', () => {
        html.removeAttribute('data-theme');
        localStorage.setItem('theme', 'active');
    });
});
