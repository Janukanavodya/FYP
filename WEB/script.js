function toggleButton() {
    const checkbox = document.getElementById('terms-checkbox');
    const button = document.getElementById('start-scan-button');
    const errorMessage = document.getElementById('error-message');
    if (checkbox.checked) {
        button.disabled = false;
        errorMessage.style.display = 'none';
    } else {
        button.disabled = true;
        errorMessage.style.display = 'block';
    }
}
