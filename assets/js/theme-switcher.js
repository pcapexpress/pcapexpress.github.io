// Wait for the DOM to load
document.addEventListener('DOMContentLoaded', () => {
    const btnActive = document.getElementById('btn-active');
    const btnStealth = document.getElementById('btn-stealth');
    const htmlElement = document.documentElement;

    // 1. Check for saved theme in localStorage
    const savedTheme = localStorage.getItem('theme') || 'active';
    htmlElement.setAttribute('data-theme', savedTheme);

    // 2. Switch to Stealth Mode
    btnStealth.addEventListener('click', () => {
        htmlElement.setAttribute('data-theme', 'stealth');
        localStorage.setItem('theme', 'stealth');
    });

    // 3. Switch to Active Mode
    btnActive.addEventListener('click', () => {
        htmlElement.setAttribute('data-theme', 'active');
        localStorage.setItem('theme', 'active');
    });
});
