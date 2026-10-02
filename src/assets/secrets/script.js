let uuid, password, uriPath;
generateCredentials();

// 背景 iframe：URL 池随机（带随机 query 绕过 5 分钟缓存，每次刷新换背景）
(function initFallbackBg() {
    const bg = document.getElementById('fallback-bg');
    if (bg) {
        bg.src = '/img?t=' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    }
})();

function generateUUID() {
    return crypto.randomUUID();
}

function generateStrongPassword() {
    const charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:',.<>?";
    let password = '';
    const randomValues = new Uint8Array(16);
    crypto.getRandomValues(randomValues);

    for (let i = 0; i < 16; i++) {
        password += charset[randomValues[i] % charset.length];
    }
    return password;
}

function generateSubURIPath() {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$&*_-+;:,.";
    let uriPath = '';
    const randomValues = new Uint8Array(16);
    crypto.getRandomValues(randomValues);

    for (let i = 0; i < 16; i++) {
        uriPath += charset[randomValues[i] % charset.length];
    }
    return uriPath;
}

function generateCredentials() {
    uuid = generateUUID();
    password = generateStrongPassword();
    uriPath = generateSubURIPath();

    document.getElementById('uuid').textContent = uuid;
    document.getElementById('tr-password').textContent = password;
    document.getElementById('sub-path').textContent = uriPath;
}

window.copyToClipboard = function (elementId) {
    const textToCopy = elementId 
        ? document.getElementById(elementId).textContent
        : `UUID=${uuid}\nTR_PASS=${password}\nSUB_PATH=${uriPath}`;

    navigator.clipboard.writeText(textToCopy)
        .then(() => alert('✅ Copied to clipboard!'))
        .catch(err => console.error('Failed to copy text:', err));
}