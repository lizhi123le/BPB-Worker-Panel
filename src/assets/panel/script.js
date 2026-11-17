const form = document.getElementById("configForm");
const [
    selectElements,
    numInputElements,
    inputElements,
    textareaElements,
    checkboxElements
] = [
    'select',
    'input[type=number]',
    'input:not([type=file])',
    'textarea',
    'input[type=checkbox]'
].map(query => form.querySelectorAll(query));

// P-05（第三方 CDN 供应链）：本页原先还用 `<script type="module">` 从 `cdn.skypack.dev`
// **无版本号**地动态 import country-flag-emoji-polyfill，那段已删除。
// 全仓没有任何 `polyfillCountryFlagEmojis` 消费点：国旗在 fetchIPInfo 里用
// `String.fromCodePoint(...)` 自己把两位区域码拼成区域指示符（见 updateUI 的 flag）。
// 所以删掉它功能不受影响，唯一差别是：系统字体没有国旗 emoji 时（典型是 Windows）
// 国旗会退化成两个字母的国家代码（IR / US），而不是彩旗 —— 可接受；
// 而「CDN 被投毒即接管面板（可读订阅密钥、可改口令）」不可接受。
// 仍依赖 CDN 的只剩：cdnjs 的 font-awesome + qrcodejs（现已带 SRI，见 index.html）、
// Google Fonts（CSS 按 UA 动态生成，无法加 SRI）。
// ⚠ R-12：这两张端口表的**集合**必须与 src/common/init.ts 的 DEFAULT_HTTP_PORTS /
// DEFAULT_HTTPS_PORTS 逐字一致（顺序可以不同：服务端只用 includes 判成员，顺序不可观测）。
// R-12：端口表由构建期从 src/common/ports.json **注入**（占位符替换），与 init.ts 读的是同一份，
// 不再需要面板侧手工同步副本。顺序即本面板拼 settings.ports 的顺序 = 订阅节点端口顺序，
// 改动顺序会改变订阅输出，非必要不要动（见 ports.json 的 _note）。
// ⚠ 直接双击打开本文件时这两个标识符是 undefined —— 属预期：它只在构建产物里被替换。
const defaultHttpsPorts = __DEFAULT_HTTPS_PORTS__;
const defaultHttpPorts = __DEFAULT_HTTP_PORTS__;

// 背景 iframe：URL 池随机（带随机 query 绕过 5 分钟缓存，每次刷新换背景）
(function initFallbackBg() {
    const bg = document.getElementById('fallback-bg');
    if (bg) {
        bg.src = '/img?t=' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    }
})();

// 纯 UI 事件与网络无关：先注册，保证下面任何一个提前 return / 跳转都不会把它们跳过。
// （它们原先写在 fetch 的 finally 里，失败路径上语义上是「顺便」注册的，很容易被后来的
// 提前 return 静默漏掉；这里独立出来。）
window.onclick = (event) => {
    const qrModal = document.getElementById('qrModal');
    const qrcodeContainer = document.getElementById('qrcode-container');

    if (event.target == qrModal) {
        qrModal.style.display = "none";
        qrcodeContainer.lastElementChild.remove();
    }
}

document.querySelectorAll(".toggle-password").forEach(toggle => {
    toggle.addEventListener("click", function () {
        const input = this.previousElementSibling;
        const isPassword = input.type === "password";
        input.type = isPassword ? "text" : "password";
        this.textContent = isPassword ? "visibility" : "visibility_off";
    });
});

function redirectToLogin() {
    window.location.href = '/login';
}

// 首屏加载失败时不能渲染空壳：给出可见提示，并整块禁用配置表单
// （含 Apply / 重置 / 导出 / 导入），否则用户看到一个字段全空、
// Apply 永远 disabled 却「看起来正常」的面板，还会以为是自己没填对。
function showPanelLoadError(message) {
    const configForm = document.getElementById('configForm');
    if (!configForm) return;

    const banner = document.createElement('div');
    banner.id = 'panel-load-error';
    banner.setAttribute('role', 'alert');
    banner.style.cssText = [
        'margin: 0 0 16px',
        'padding: 12px 16px',
        'border: 1px solid rgba(200, 40, 40, 0.55)',
        'border-radius: 8px',
        'background: rgba(200, 40, 40, 0.15)',
        'color: var(--color-text-primary, inherit)',
        'line-height: 1.6',
        'word-break: break-word'
    ].join(';');
    banner.textContent = `⛔ Failed to load panel settings — ${message}\n💡 Nothing on this page can be saved until it loads. Please reload, or login again if your session expired.`;

    configForm.before(banner);
    configForm.querySelectorAll('input, select, textarea, button').forEach(elm => elm.disabled = true);
    document.getElementById('applyButton')?.classList.add('disabled');
    document.body.style.cursor = 'default';

    alert(
        '⛔ Failed to load panel settings!\n' +
        `💡 ${message}\n\n` +
        'Please reload the page, or login again if your session expired.'
    );
}

// 首屏 fetch：会话过期时后端会 302 到 /login，或者直接返回 200 的 HTML 登录页。
// 旧代码直接 response.json()，两种情况都会抛错，而 catch 只打一行 console、
// finally 仍然照常执行 -> 页面带着空表单看起来「正常」，并且 fetchSystemStatus()
// 还会继续每 30 秒轮询一次 /panel/region。所以这里先判 response.ok /
// redirected / content-type，失败即跳登录页或显式报错并禁用表单。
fetch('/panel/settings')
    .then(response => {
        if (response.redirected || response.status === 401) {
            redirectToLogin();
            return null;
        }

        if (!response.ok) {
            throw new Error(`status ${response.status} - ${response.statusText}`);
        }

        // 会话过期时后端也可能直接返回 HTML 登录页（200），json() 一样会抛错
        const contentType = response.headers.get('content-type') || '';

        if (!contentType.includes('application/json')) {
            redirectToLogin();
            return null;
        }

        return response.json();
    })
    .then(payload => {
        if (!payload) return; // 已经跳转登录页，不再渲染

        const { success, status, message, body } = payload;

        if (!success) {
            throw new Error(`status ${status} - ${message}`);
        }

        const { subPath, proxySettings } = body;
        globalThis.subPath = encodeURIComponent(subPath);
        initiatePanel(proxySettings);
        // 只有初始化成功后才需要状态轮询；会话失效时不再做无意义的 30s 轮询
        globalThis.panelReady = true;
        fetchSystemStatus();
    })
    .catch(error => {
        console.error("Data query error:", error.message || error);
        showPanelLoadError(error.message || String(error));
    });

function initiatePanel(proxySettings) {
    const {
        VLConfigs,
        TRConfigs,
        xpConfigs,
        ports,
        xrayUdpNoises
    } = proxySettings;

    Object.assign(globalThis, {
        // XHTTP 也计入「至少选一个」：它本身就是一种可独立使用的 VLESS 传输，
        // 关掉 VLESS/Trojan 只留 XHTTP 仍是合法订阅（只出 VLESS-XHTTP 节点）。
        activeProtocols: VLConfigs + TRConfigs + xpConfigs,
        activeTlsPorts: ports.filter(port => defaultHttpsPorts.includes(port)),
        xrayNoiseCount: xrayUdpNoises.length,
    });

    populatePanel(proxySettings);
    renderPortsBlock(ports.map(Number));
    renderUdpNoiseBlock(xrayUdpNoises);
    initiateForm();
    fetchIPInfo();
}

function populatePanel(proxySettings) {
    document.getElementById("doh").textContent = `${window.origin}/dns-query/${decodeURIComponent(globalThis.subPath)}`;
    selectElements.forEach(elm => elm.value = proxySettings[elm.id]);
    // 出站方式 (qj)：由 proxyOnly/proxyDegrade 反推下拉值
    const outboundMode = proxySettings.proxyOnly ? 'only' : proxySettings.proxyDegrade ? 'no' : 'default';
    document.getElementById('outboundMode').value = outboundMode;
    checkboxElements.forEach(elm => elm.checked = proxySettings[elm.id]);
    inputElements.forEach(elm => elm.value = proxySettings[elm.id] || "");
    textareaElements.forEach(elm => {
        const key = elm.id;
        const element = document.getElementById(key);
        const value = proxySettings[key]?.join('\r\n');
        const rowsCount = proxySettings[key]?.length || 0;
        element.style.height = 'auto';
        if (rowsCount) element.rows = rowsCount;
        element.value = value;
    });
}

function initiateForm() {
    const configForm = document.getElementById('configForm');
    globalThis.initialFormData = new FormData(configForm);
    enableApplyButton();

    configForm.addEventListener('input', enableApplyButton);
    configForm.addEventListener('change', enableApplyButton);
    const textareas = document.querySelectorAll("textarea");

    textareas.forEach(textarea => {
        textarea.addEventListener('input', function () {
            this.style.height = 'auto';
            this.style.height = `${this.scrollHeight}px`;
        });
    });

    handleFragmentMode();
}

function hasFormDataChanged() {
    const formDataToObject = (formData) => Object.fromEntries(formData.entries());
    const configForm = document.getElementById('configForm');
    const currentFormData = new FormData(configForm);

    const initialFormDataObj = formDataToObject(globalThis.initialFormData);
    const currentFormDataObj = formDataToObject(currentFormData);

    return JSON.stringify(initialFormDataObj) !== JSON.stringify(currentFormDataObj);
}

function enableApplyButton() {
    const applyButton = document.getElementById('applyButton');
    const isChanged = hasFormDataChanged();
    applyButton.disabled = !isChanged;
    applyButton.classList.toggle('disabled', !isChanged);
}

function openResetPass() {
    const resetPassModal = document.getElementById('resetPassModal');
    resetPassModal.style.display = "block";
    document.body.style.overflow = "hidden";
}

function closeResetPass() {
    const resetPassModal = document.getElementById('resetPassModal');
    resetPassModal.style.display = "none";
    document.body.style.overflow = "";
}

function closeQR() {
    const qrModal = document.getElementById('qrModal');
    const qrcodeContainer = document.getElementById('qrcode-container');
    qrModal.style.display = "none";
    qrcodeContainer.lastElementChild.remove();
}

async function getIpDetails(ip) {
    try {
        const response = await fetch('/panel/my-ip', { method: 'POST', body: ip });
        const { success, status, message, body } = await response.json();

        if (!success) {
            throw new Error(`status ${status} - ${message}`);
        }

        return body;
    } catch (error) {
        console.error("Fetching IP error:", error.message || error)
    }
}

async function fetchIPInfo() {
    const refreshIcon = document.getElementById("refresh-geo-location").querySelector('i');
    refreshIcon.classList.add('fa-spin');
    const updateUI = (ip = '-', country = '-', countryCode = '-', city = '-', isp = '-', cfIP) => {
        const flag = countryCode !== '-' ? String.fromCodePoint(...[...countryCode].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : '';
        const updateContent = (id, content) => document.getElementById(id).textContent = content;
        updateContent(cfIP ? 'cf-ip' : 'ip', ip);
        updateContent(cfIP ? 'cf-country' : 'country', `${country} ${flag}`);
        updateContent(cfIP ? 'cf-city' : 'city', city);
        updateContent(cfIP ? 'cf-isp' : 'isp', isp);
    };

    try {
        const response = await fetch('https://ipv4.geojs.io/v1/ip.json' + '?nocache=' + Date.now(), { cache: "no-store" });
        
        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`Fetch Other targets IP failed with status ${response.status} at ${response.url} - ${errorMessage}`);
        }

        const { ip } = await response.json();
        const { country, countryCode, city, isp } = await getIpDetails(ip);
        updateUI(ip, country, countryCode, city, isp);
        refreshIcon.classList.remove('fa-spin');
    } catch (error) {
        console.error("Fetching IP error:", error.message || error)
    }

    try {
        const response = await fetch('https://ipv4.icanhazip.com/?nocache=' + Date.now(), { cache: "no-store" });

        if (!response.ok) {
            const errorMessage = await response.text();
            throw new Error(`Fetch Cloudflare targets IP failed with status ${response.status} at ${response.url} - ${errorMessage}`);
        }

        const ip = await response.text();
        const { country, countryCode, city, isp } = await getIpDetails(ip);
        updateUI(ip, country, countryCode, city, isp, true);
        refreshIcon.classList.remove('fa-spin');
    } catch (error) {
        console.error("Fetching IP error:", error.message || error)
    }
}

function downloadWarpConfigs(isAmnezia) {
    const client = isAmnezia ? "?app=amnezia" : "";
    window.location.href = "/panel/get-warp-configs" + client;
}

function generateSubUrl(path, app, tag, singboxType) {
    const url = new URL(window.location.href);
    url.pathname = `/sub/${path}/${globalThis.subPath}`;
    app && url.searchParams.append('app', app);

    if (tag) {
        url.hash = `💦 BPB ${tag}`;
    }

    return singboxType
        ? `sing-box://import-remote-profile?url=${url.href}`
        : url.href;
}

function subURL(path, app, tag, singboxType) {
    const url = generateSubUrl(path, app, tag, singboxType);
    copyToClipboard(url);
}

async function dlURL(path, app) {
    const url = generateSubUrl(path, app);

    try {
        const response = await fetch(url);
        const data = await response.text();

        if (!response.ok) {
            throw new Error(`status ${response.status} at ${response.url} - ${data}`);
        }

        downloadJSON(data, "config.json");
    } catch (error) {
        console.error("Download error:", error.message || error);
    }
}

function downloadJSON(data, fileName) {
    const blob = new Blob([data], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function exportSettings() {
    const form = validateSettings();
    // validateSettings() 校验失败时返回 false（B-39 的防御性改造）。原先会一路
    // JSON.stringify(false) → 导出一个内容为 `false` 的 .dat，看起来成功、导入时全空。
    if (!form) return;
    const data = JSON.stringify(form, null, 4);
    const encodedData = btoa(unescape(encodeURIComponent(data)));
    downloadJSON(encodedData, `BPB-settings.dat`);
}

function importSettings() {
    const input = document.getElementById('fileInput');
    input.value = '';
    input.click();
}

async function uploadSettings(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
        const text = await file.text();
        const data = JSON.parse(decodeURIComponent(escape(atob(text))));
        updateSettings(event, data);
    } catch (err) {
        console.error('Failed to import settings:', err.message);
    }
}

function openQR(path, app, tag, title, singboxType) {
    const qrModal = document.getElementById('qrModal');
    const qrcodeContainer = document.getElementById('qrcode-container');
    const url = generateSubUrl(path, app, tag, singboxType);
    let qrcodeTitle = document.getElementById("qrcodeTitle");
    qrcodeTitle.textContent = title;
    qrModal.style.display = "block";
    let qrcodeDiv = document.createElement("div");
    qrcodeDiv.className = "qrcode";
    qrcodeDiv.style.padding = "2px";
    qrcodeDiv.style.backgroundColor = "#ffffff";
    /* global QRCode */
    new QRCode(qrcodeDiv, {
        text: url,
        width: 256,
        height: 256,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.H
    });

    qrcodeContainer.appendChild(qrcodeDiv);
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
        .then(() => alert('✅ Copied to clipboard:\n\n' + text))
        .catch(error => console.error('Failed to copy:', error));
}

async function updateWarpConfigs() {
    const confirmReset = confirm('⚠️ Are you sure?');
    if (!confirmReset) return;
    const refreshBtn = document.getElementById('warp-update');
    document.body.style.cursor = 'wait';
    refreshBtn.classList.add('fa-spin');

    try {
        const response = await fetch('/panel/update-warp', { method: 'POST', credentials: 'include' });
        const { success, status, message } = await response.json();

        if (!success) {
            alert(
                '⚠️ An error occured, Please try again!\n' +
                `⛔ ${message}`
            );

            throw new Error(`status ${status} - ${message}`);
        }

        alert('✅ Warp configs updated successfully!');
    } catch (error) {
        console.error("Updating Warp configs error:", error.message || error)
    } finally {
        // 复位必须放在 finally：fetch 被拒（离线/被拦截）或返回的不是 JSON
        // （会话过期 -> HTML）时，原来的复位语句根本执行不到，
        // 页面会永久停在 cursor: wait + 转圈的图标上。
        document.body.style.cursor = 'default';
        refreshBtn.classList.remove('fa-spin');
    }
}

function handleProtocolChange(event) {
    if (event.target.checked) {
        globalThis.activeProtocols++;
        return true;
    }

    globalThis.activeProtocols--;

    if (globalThis.activeProtocols === 0) {
        event.preventDefault();
        event.target.checked = !event.target.checked;
        alert("⛔ At least one Protocol should be selected!");
        globalThis.activeProtocols++;
        return false;
    }
}

function handlePortChange(event) {
    const portField = Number(event.target.name);

    if (event.target.checked) {
        globalThis.activeTlsPorts.push(portField);
        return true;
    }

    globalThis.activeTlsPorts = globalThis.activeTlsPorts.filter(port => port !== portField);

    if (globalThis.activeTlsPorts.length === 0) {
        event.preventDefault();
        event.target.checked = !event.target.checked;
        alert("⛔ At least one TLS port should be selected!");
        globalThis.activeTlsPorts.push(portField);
        return false;
    }
}

function handleRiskyRules(event) {
    if (event.target.checked) {
        const proceed = confirm(
            "⛔ v2ray users should set Geo Assets to Chocolate4U and download assets, otherwise configs won't connect.\n\n" +
            "❓ Proceed?"
        );

        if (!proceed) {
            event.target.checked = false;
            return;
        }
    }
}

function handleFragmentMode() {
    const fragmentMode = document.getElementById("fragmentMode").value;
    const formDataObj = Object.fromEntries(globalThis.initialFormData.entries());
    const inputs = [
        "fragmentLengthMin",
        "fragmentLengthMax",
        "fragmentIntervalMin",
        "fragmentIntervalMax"
    ];

    const configs = {
        low: [100, 200, 1, 1],
        medium: [50, 100, 1, 5],
        high: [10, 20, 10, 20],
        severe: [1, 5, 1, 5],
        custom: inputs.map(id => formDataObj[id])
    };

    inputs.forEach((id, index) => {
        const elm = document.getElementById(id);
        elm.value = configs[fragmentMode][index];
        fragmentMode !== "custom"
            ? elm.setAttribute('readonly', 'true')
            : elm.removeAttribute('readonly');
    });
}

function resetSettings() {
    const confirmReset = confirm('⚠️ This will reset all panel settings.\n\n❓ Are you sure?');
    if (!confirmReset) return;

    const resetBtn = document.getElementById("refresh-btn");
    resetBtn.classList.add('fa-spin');
    const body = { resetSettings: true };
    document.body.style.cursor = 'wait';

    fetch('/panel/reset-settings', {
        method: 'POST',
        body: JSON.stringify(body),
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(({ success, status, message, body }) => {
            if (!success) {
                throw new Error(`status ${status} - ${message}`);
            }

            initiatePanel(body);
            alert('✅ Panel settings reset to default successfully!\n💡 Please update your subscriptions.');
        })
        .catch(error => console.error("Reseting settings error:", error.message || error))
        .finally(() => {
            // 复位必须在 finally 里：fetch 被拒或返回非 JSON（会话过期 -> HTML）时，
            // 放在 .then 里的复位语句执行不到，页面会永久停在 cursor: wait + 转圈，
            // 用户再点一次（reset 真的会重写 KV）就重复提交了。
            document.body.style.cursor = 'default';
            resetBtn.classList.remove('fa-spin');
        });
}

function updateSettings(event, data) {
    event.preventDefault();
    event.stopPropagation();

    const validatedForm = validateSettings();
    if (!validatedForm) return false;

    const form = data ? data : validatedForm;
    const applyButton = document.getElementById('applyButton');
    document.body.style.cursor = 'wait';

    // Apply 是 <button>（index.html 的 #applyButton），它的可见文本来自子节点，
    // 而不是 .value（.value 只影响表单提交）—— 所以旧代码设置 value 用户什么都看不到，
    // 事后的「恢复」也纯属摆设。这里改为替换可见内容并禁用按钮（请求期间禁止重复提交），
    // 先备份原始 innerHTML 再改，恢复统一放在 finally 里。
    const applyButtonHTML = applyButton.innerHTML;
    applyButton.textContent = '⌛ Loading...';
    applyButton.disabled = true;
    applyButton.classList.add('disabled');

    fetch('/panel/update-settings', {
        method: 'PUT',
        body: JSON.stringify(form),
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(({ success, status, message }) => {

            if (status === 401) {
                alert('⚠️ Session expired! Please login again.');
                window.location.href = '/login';
            }

            if (!success) {
                throw new Error(`status ${status} - ${message}`);
            }

            initiatePanel(form);
            alert('✅ Settings applied successfully!\n💡 Please update your subscriptions.');
        })
        .catch(error => console.error("Update settings error:", error.message || error))
        .finally(() => {
            // 成功与失败都必须还原：恢复原始可见内容，并重新按「表单是否有改动」
            // 决定禁用状态（成功时 initiatePanel 会刷新 initialFormData，按钮应再次变灰）
            document.body.style.cursor = 'default';
            applyButton.innerHTML = applyButtonHTML;
            enableApplyButton();
        });
}

function parseElmValues(id) {
    const val = document.getElementById(id)?.value;
    if (!val) return [];
    return val.split('\n')
        .map(value => value.trim())
        .filter(Boolean)
        .flatMap(line => {
            if (line.includes(',') && !line.startsWith('#') && !line.startsWith('//')) {
                return line.split(',').map(s => s.trim()).filter(Boolean);
            }
            return [line];
        });
}

function getElmValue(id) {
    return document.getElementById(id).value?.trim();
}

function isDomain(value) {
    const domainRegex = /^(?=.{1,253}$)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+[a-zA-Z]{2,63}$/;
    return domainRegex.test(value);
}

function isIPv4(value) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    return ipv4Regex.test(value);
}

function isIPv4CIDR(value) {
    const ipv4CidrRegex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/;
    return ipv4CidrRegex.test(value);
}

function isIPv6(value) {
    const ipv6Regex = /^\[(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6}|:(?::[a-fA-F0-9]{1,4}){1,7})\]$/;
    return ipv6Regex.test(value);
}

function isIPv6CIDR(value) {
    const ipv6CidrRegex = /^(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6}|:(?::[a-fA-F0-9]{1,4}){1,7}|::)(?:\/(?:12[0-8]|1[01]?[0-9]|[0-9]?[0-9]))?$/;
    return ipv6CidrRegex.test(value);
}

function parseHostPort(input) {
    const regex = /^(?<host>\[.*?\]|[^:]+)(?::(?<port>\d+))?$/;
    const match = input.match(regex);

    if (match) {
        return {
            host: match.groups.host,
            port: match.groups.port ? +match.groups.port : null
        };
    }

    if ((input.match(/:/g) || []).length >= 2) {
        const lastColon = input.lastIndexOf(':');
        const after = input.slice(lastColon + 1);
        if (/^\d+$/.test(after)) {
            const hostPart = input.slice(0, lastColon);
            if (hostPart.includes(':') && !hostPart.endsWith(':')) {
                return { host: `[${hostPart}]`, port: +after };
            }
        }
        return { host: `[${input}]`, port: null };
    }

    return null;
}

function isValidHostName(value, isHost) {
    const hostPort = parseHostPort(value.trim());
    if (!hostPort) return false;
    const { host, port } = hostPort;
    if (port && (port > 65535 || port < 1)) return false;
    if (isHost && !port) return false;

    return isIPv6(host) || isIPv4(host) || isDomain(host);
}

function validateRemoteDNS() {
    let url;
    const dns = getElmValue("remoteDNS");

    try {
        url = new URL(dns);
    } catch (error) {
        alert("⛔ Invalid DNS, Please enter a URL.");
        return false;
    }

    const cloudflareDNS = [
        '1.1.1.1',
        '1.0.0.1',
        '1.1.1.2',
        '1.0.0.2',
        '1.1.1.3',
        '1.0.0.3',
        '2606:4700:4700::1111',
        '2606:4700:4700::1001',
        '2606:4700:4700::1112',
        '2606:4700:4700::1002',
        '2606:4700:4700::1113',
        '2606:4700:4700::1003',
        'cloudflare-dns.com',
        'security.cloudflare-dns.com',
        'family.cloudflare-dns.com',
        'one.one.one.one',
        '1dot1dot1dot1'
    ];

    if (!["tcp:", "https:", "tls:"].includes(url.protocol)) {
        alert("⛔ Please enter TCP, DoH or DoT servers.");
        return false;
    }

    if (cloudflareDNS.includes(url.hostname)) {
        alert(
            "⛔ Cloudflare DNS is not allowed for workers.\n" +
            "💡 Please use other public DNS servers like Google, Adguard..."
        );

        return false;
    }

    return true;
}

function validateSanctionDns() {
    const dns = getElmValue("antiSanctionDNS");
    let host;

    try {
        const url = new URL(dns);
        host = url.hostname;
    } catch {
        host = dns;
    }

    const isValid = isValidHostName(host, false);

    if (!isValid) {
        alert(
            '⛔ Invalid IPs or Domains.\n' +
            `⚠️ ${host}`
        );

        return false;
    }

    return true;
}

function validateWarpDNS() {
    const dns = getElmValue("warpRemoteDNS");
    const isValid = isIPv4(dns);

    if (!isValid) {
        alert(
            '⛔ Invalid Warp DNS.\n' +
            '💡 Please fill in an IPv4 address (UDP DNS).\n\n' +
            `⚠️ ${dns}`
        );

        return false;
    }

    return true;
}

function validateLocalDNS() {
    const dns = getElmValue("localDNS");
    const isValid = isIPv4(dns) || dns === 'localhost';

    if (!isValid) {
        alert(
            '⛔ Invalid local DNS.\n' +
            '💡 Please fill in an IPv4 address or "localhost".\n\n' +
            `⚠️ ${dns}`
        );

        return false;
    }

    return true;
}

function validateCustomRules() {
    const invalidDomainIpValues = [
        'customBypassRules',
        'customBlockRules'
    ].flatMap(parseElmValues)
        .filter(value => !isIPv4CIDR(value) && !isIPv6CIDR(value) && !isDomain(value));

    const invalidDomainValues = parseElmValues('customBypassSanctionRules').filter(value => !isDomain(value));

    if (invalidDomainIpValues.length) {
        alert(
            '⛔ Invalid IPs, Domains or IP ranges.\n' +
            '💡 Please enter each value in a new line.\n\n' +
            invalidDomainIpValues.map(val => `⚠️ ${val}`).join('\n')
        );

        return false;
    }

    if (invalidDomainValues.length) {
        alert(
            '⛔ Invalid Domains.\n💡 Please enter each value in a new line.\n\n' +
            invalidDomainValues.map(val => `⚠️ ${val}`).join('\n')
        );

        return false;
    }

    return true;
}

function parseAddressEntry(value) {
    return value.includes('#') ? value.split('#')[0].trim() : value;
}

/**
 * 条目是否为代理写法。与后端 parseCleanProxy 的启发式保持一致（忽略 #备注）：
 *   socks:// / socks5:// 一律是代理；
 *   http(s):// 仅在「带凭据」或「有端口且无路径」或「无路径的 IP 字面量」时是代理，
 *   其余（带路径、无凭据、非 IP）仍是远程清单 URL。
 * 用途：代理条目大小写敏感（user/pass、#备注），提交去重时不得 toLowerCase。
 */
function isProxyLikeEntry(item) {
    if (/^socks5?:\/\//i.test(item)) return true;
    if (!/^https?:\/\//i.test(item)) return false;

    const afterScheme = item.slice(item.indexOf('://') + 3);
    const authority = afterScheme.split('#')[0];
    if (authority.includes('@')) return true;   // 带凭据 → 代理

    const pathIndex = authority.search(/[/?]/);
    const hasPath = pathIndex !== -1 && authority.slice(pathIndex).replace(/^\//, '') !== '';
    if (hasPath) return false;                  // 带路径 → 远程清单 URL

    const hasPort = /:\d+$/.test(authority);
    const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}(?::\d+)?$/.test(authority)
        || /^\[[0-9a-fA-F:.]+\](?::\d+)?$/.test(authority);
    return hasPort || isIpLiteral;
}

function validateMultipleHostNames() {
    // cleanIPs 允许代理条目（socks / socks5 / http(s)，由服务端生成独立可选节点）；
    // customCdnAddrs 仍是纯地址列表，代理写法在那里没有意义，继续按主机名校验。
    const invalidValues = [
        { id: 'cleanIPs', allowProxy: true },
        { id: 'customCdnAddrs', allowProxy: false }
    ].flatMap(({ id, allowProxy }) => parseElmValues(id).filter(value => {
        // http(s):// 交给服务端 resolveUrlEntries / 代理识别处理，不做主机名校验
        if (/^https?:\/\//i.test(value)) return false;
        if (allowProxy && /^socks5?:\/\//i.test(value)) return false;
        return !isValidHostName(parseAddressEntry(value));
    }));

    if (invalidValues.length) {
        alert(
            '⛔ Invalid IPs or Domains.\n' +
            '💡 Please enter each value in a new line.\n\n' +
            invalidValues.map(ip => `⚠️ ${ip}`).join('\n')
        );

        return false;
    }

    return true;
}

function validateProxyIPs() {
    const invalidValues = parseElmValues('proxyIPs')
        .filter(value => {
            // URLs are allowed — resolved server-side by resolveUrlEntries
            if (value.startsWith('http://') || value.startsWith('https://')) return false;
            // Strip #comment and @REGION before hostname validation
            const noComment = value.indexOf('#') !== -1 ? value.slice(0, value.indexOf('#')).trim() : value;
            const cleanValue = noComment.lastIndexOf('@') !== -1
                ? noComment.slice(0, noComment.lastIndexOf('@')).trim()
                : noComment;
            return !isValidHostName(cleanValue);
        });

    if (invalidValues.length) {
        alert(
            '⛔ Invalid proxy IPs.\n' +
            '💡 Please enter each value in a new line.\n\n' +
            invalidValues.map(ip => `⚠️ ${ip}`).join('\n')
        );

        return false;
    }

    return true;
}

function validateNAT64Prefixes() {
    const invalidValues = parseElmValues('prefixes')
        .filter(value => !isIPv6(value));

    if (invalidValues.length) {
        alert(
            '⛔ Invalid NAT64 prefix.\n' +
            '💡 Please enter each prefix in a new line using [].\n\n' +
            invalidValues.map(ip => `⚠️ ${ip}`).join('\n')
        );

        return false;
    }

    return true;
}

function validateWarpEndpoints() {
    const invalidEndpoints = parseElmValues('warpEndpoints')
        .filter(value => !isValidHostName(value, true));

    if (invalidEndpoints.length) {
        alert(
            '⛔ Invalid endpoint.\n\n' +
            invalidEndpoints.map(endpoint => `⚠️ ${endpoint}`).join('\n')
        );

        return false;
    }

    return true;
}

function validateMinMax() {
    const getValue = (id) => parseInt(getElmValue(id), 10);

    const fields = [
        ['fragmentLengthMin', 'fragmentLengthMax', 'Fragment Length'],
        ['fragmentIntervalMin', 'fragmentIntervalMax', 'Fragment Interval'],
        ['fragmentMaxSplitMin', 'fragmentMaxSplitMax', 'Fragment Max Split'],
        ['noiseCountMin', 'noiseCountMax', 'Noise Count'],
        ['noiseSizeMin', 'noiseSizeMax', 'Noise Size'],
        ['noiseDelayMin', 'noiseDelayMax', 'Noise Delay'],
        ['amneziaNoiseSizeMin', 'amneziaNoiseSizeMax', 'Amnezia Noise Size']
    ];

    for (const [minId, maxId, label] of fields) {
        const min = getValue(minId);
        const max = getValue(maxId);

        if (min > max) {
            alert(`⛔ ${label}: Minimum cannot be bigger than Maximum!`);
            return false;
        }
    }

    return true;
}

function validateChainProxy() {
    let chainProxy = getElmValue('outProxy');
    if (!chainProxy) return true;
    const isVMess = /vmess:\/\/.+$/.test(chainProxy);
    const isOthers = /(http|socks|socks5|vless|trojan|ss):\/\/[^\s@]+@[^\s:]+:[^\s]+/.test(chainProxy);

    if (!isVMess && !isOthers) {
        alert(
            '⛔ Invalid Config!\n' +
            '💡 Standard formats are:\n\n' +
            ' + (socks or socks5 or http)://user:pass@server:port\n' +
            ' + (socks or socks5 or http)://base64@server:port\n' +
            ' + vless://uuid@server:port...\n' +
            ' + vmess://base64\n' +
            ' + trojan://password@server:port...\n' +
            ' + ss://base64@server:port...'
        );

        return false;
    }

    // new URL() 对畸形输入会抛 TypeError；vmess 的 atob/JSON.parse 对损坏的
    // base64/JSON 也会抛。异常会一路冲出 validateSettings -> updateSettings ->
    // submit 监听器，结果是点击 Apply 完全没反应（连 alert 都没有、也不发请求），
    // 面板从此无法保存。所以这两段解析必须在这里收敛成 false + 明确提示。
    let protocol, username, security, type;

    try {
        const config = new URL(chainProxy);
        ({ protocol, username } = config);
        security = config.searchParams.get('security');
        type = config.searchParams.get('type');
    } catch (error) {
        alert(
            '⛔ Invalid chain proxy URL!\n' +
            '💡 Standard formats are:\n\n' +
            ' + (socks or socks5 or http)://user:pass@server:port\n' +
            ' + (socks or socks5 or http)://base64@server:port\n' +
            ' + vless://uuid@server:port...\n' +
            ' + vmess://base64\n' +
            ' + trojan://password@server:port...\n' +
            ' + ss://base64@server:port...'
        );

        return false;
    }

    if (isVMess) {
        try {
            // config.host 是 vmess:// 后面的整段 Base64，解出来应为一个 JSON 对象
            const vmConfig = JSON.parse(atob(config.host));
            username = vmConfig.id;
            security = vmConfig.tls;
            type = vmConfig.net;
        } catch (error) {
            alert(
                '⛔ Invalid Config!\n' +
                '💡 The vmess:// payload is not valid Base64 encoded JSON.'
            );

            return false;
        }
    }

    if (['vless:', 'trojan:', 'vmess:'].includes(protocol)) {
        if (!username) {
            alert(
                '⛔ Invalid Config!\n' +
                '💡 Config URL should contain UUID or Password.'
            );

            return false;
        }

        if (security && !['tls', 'none', 'reality'].includes(security)) {
            alert(
                '⛔ Invalid Config!\n' +
                '💡 VLESS, VMess or Trojan security can be TLS, Reality or None.'
            );

            return false;
        }

        if (!['tcp', 'raw', 'ws', 'grpc', 'httpupgrade'].includes(type)) {
            alert(
                '⛔ Invalid Config!\n' +
                '💡 VLESS, VMess or Trojan transmission can be tcp, ws, grpc or httpupgrade.'
            );

            return false;
        }
    }

    return true;
}

function validateKnockerNoise() {
    const regex = /^(none|quic|random|[0-9A-Fa-f]+)$/;
    const knockerNoise = getElmValue("knockerNoiseMode");

    if (!regex.test(knockerNoise)) {
        alert(
            '⛔ Invalid noise  mode.\n' +
            '💡 Please use "none", "quic", "random" or a valid hex value.'
        );

        return false;
    }

    return true;
}

function validateXrayNoises(fields) {
    const [modes, packets, delaysMin, delaysMax] = fields;
    const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    let submisionError = false;

    modes.forEach((mode, index) => {
        if (Number(delaysMin[index]) > Number(delaysMax[index])) {
            alert('⛔ The minimum noise delay should be smaller or equal to maximum!');
            submisionError = true;
            return;
        }

        switch (mode) {
            case 'base64': {
                if (!base64Regex.test(packets[index])) {
                    alert('⛔ The Base64 noise packet is not a valid base64 value!');
                    submisionError = true;
                }

                break;
            }
            case 'rand': {
                if (!(/^\d+-\d+$/.test(packets[index]))) {
                    alert('⛔ The Random noise packet should be a range like 0-10 or 10-30!');
                    submisionError = true;
                }

                const [min, max] = packets[index].split("-").map(Number);

                if (min > max) {
                    alert('⛔ The minimum Random noise packet should be smaller or equal to maximum!');
                    submisionError = true;
                }

                break;
            }
            case 'hex': {
                if (!(/^(?=(?:[0-9A-Fa-f]{2})*$)[0-9A-Fa-f]+$/.test(packets[index]))) {
                    alert(
                        '⛔ The Hex noise packet is not a valid hex value!\n' +
                        '💡 It should have even length and consisted of 0-9, a-f and A-F.'
                    );
                    submisionError = true;
                }

                break;
            }
            case 'array': {
                const valid = packets[index]
                    .split(',')
                    .every(n => /^\d+$/.test(n) && +n >= 0 && +n <= 255);

                if (!valid) {
                    alert('⛔ The values should be comma separated numbers between 0-255');
                    submisionError = true;
                }

                break;
            }
        }
    });

    return !submisionError;
}

function validateEchConfig() {
    const echServerName = document.getElementById("echServerName").value;

    if (!echServerName) return true;

    const names = echServerName.split('\n').map(v => v.trim()).filter(Boolean);
    for (const name of names) {
        if (!isDomain(name)) {
            alert('⛔ Each ECH Server Name should be a valid domain!');
            return false;
        }
    }

    return true;
}

function validateHostSniList() {
    const hostSniList = document.getElementById("hostSniList").value;

    if (!hostSniList) return true;

    const names = hostSniList.split('\n').map(v => v.trim()).filter(Boolean);
    for (const name of names) {
        if (!isDomain(name)) {
            alert('⛔ Each HOST/SNI should be a valid domain!');
            return false;
        }
    }

    return true;
}

function isValidUpstreamProxyURL(value) {
    // Mirror backend parseUpstreamProxyConfig (common.ts L390-447)
    const lower = value.toLowerCase();
    let addr = value;
    let kind; // 'socks5' | 'tunnel' | 'secure-tunnel'

    if (lower.startsWith('https://')) {
        kind = 'secure-tunnel';
        addr = value.slice('https://'.length);
    } else if (lower.startsWith('http://')) {
        kind = 'tunnel';
        addr = value.slice('http://'.length);
    } else if (lower.startsWith('socks5://')) {
        kind = 'socks5';
        addr = value.slice('socks5://'.length);
    } else if (lower.startsWith('socks://')) {
        kind = 'socks5';
        addr = value.slice('socks://'.length);
    } else {
        return false;
    }

    // Strip trailing path — backend L407-408
    const pathIdx = addr.indexOf('/');
    if (pathIdx >= 0) addr = addr.slice(0, pathIdx);
    if (!addr) return false;

    // Strip user:pass@ — backend L414-420
    const atIdx = addr.lastIndexOf('@');
    if (atIdx >= 0) {
        const authPart = addr.slice(0, atIdx);
        if (!authPart || authPart.indexOf(':') < 0) return false;
        addr = addr.slice(atIdx + 1);
    }

    // Parse host:port — backend L432-444
    const parts = addr.split(':');
    const lastPart = parts.pop();
    let port = Number(lastPart);

    if (isNaN(port)) {
        // Tunnel allows omitted port — defaults 80/443 (backend L436-439)
        if (kind === 'socks5') return false;
        parts.push(lastPart);
        port = kind === 'secure-tunnel' ? 443 : 80;
    }

    const hostname = parts.join(':');
    if (!hostname) return false;

    // IPv6 must be bracketed — backend L443-444
    if (hostname.indexOf(':') >= 0 && !/^\[.*\]$/.test(hostname)) return false;

    // Validate host: strip brackets for IPv6 check
    const hostClean = hostname.replace(/^\[|\]$/g, '');
    if (!isIPv4(hostClean) && !isIPv6(hostname) && !isDomain(hostClean)) return false;

    // Validate port range
    if (port < 1 || port > 65535) return false;

    return true;
}

function validateUpstreamProxy() {
    const upstreamProxy = getElmValue('upstreamProxy');
    if (!upstreamProxy || !upstreamProxy.trim()) return true;

    const value = upstreamProxy.trim();

    // Check if input has a URL scheme prefix
    if (/^(socks5?|https?):\/\//i.test(value)) {
        if (!isValidUpstreamProxyURL(value)) {
            alert(
                '⛔ Invalid Upstream proxy URL!\n' +
                '💡 Supported formats:\n' +
                '  socks5://host:port\n' +
                '  socks5://user:pass@host:port\n' +
                '  http://host:port\n' +
                '  https://host:port\n' +
                '  host:port (legacy)'
            );
            return false;
        }
    } else {
        // Legacy bare host:port format
        if (!isValidHostName(value, true)) {
            alert(
                '⛔ Invalid Upstream proxy!\n' +
                '💡 Supported formats:\n' +
                '  socks5://host:port\n' +
                '  socks5://user:pass@host:port\n' +
                '  http://host:port\n' +
                '  https://host:port\n' +
                '  host:port (legacy)'
            );
            return false;
        }
    }

    return true;
}

function validateSettings() {
    // 防御性兜底：校验里任何未预料的异常（比如将来某个校验函数抛错）都必须
    // 收敛成本函数返回 false + 一次 alert，绝不能冲出 submit 监听器 ——
    // 那会让 Apply 彻底静默失灵（没有 alert、也不发请求），只能刷新页面才能恢复。
    // 具体逻辑放在 validateSettingsForm 里，避免为了包一层 try 重排上百行缩进。
    try {
        return validateSettingsForm();
    } catch (error) {
        console.error('Settings validation error:', error.message || error);
        alert(
            '⛔ Unexpected error while validating settings!\n' +
            `💡 ${error.message || error}`
        );

        return false;
    }
}

function validateSettingsForm() {
    const configForm = document.getElementById('configForm');
    const formData = new FormData(configForm);

    const fields = [
        'udpXrayNoiseMode',
        'udpXrayNoisePacket',
        'udpXrayNoiseDelayMin',
        'udpXrayNoiseDelayMax',
        'udpXrayNoiseCount'
    ].map(field => formData.getAll(field));

    const validations = [
        validateRemoteDNS(),
        validateSanctionDns(),
        validateLocalDNS(),
        validateWarpDNS(),
        validateMultipleHostNames(),
        validateProxyIPs(),
        validateNAT64Prefixes(),
        validateWarpEndpoints(),
        validateMinMax(),
        validateUpstreamProxy(),
        validateChainProxy(),
        validateKnockerNoise(),
        validateXrayNoises(fields),
        validateCustomRules(),
        validateEchConfig(),
        validateHostSniList()
    ];

    if (!validations.every(Boolean)) {
        return false;
    }

    const form = Object.fromEntries(formData.entries());
    const [modes, packets, delaysMin, delaysMax, counts] = fields;

    form.xrayUdpNoises = modes.map((mode, index) => ({
        type: mode,
        packet: packets[index],
        delay: `${delaysMin[index]}-${delaysMax[index]}`,
        count: counts[index]
    }));

    form.ports = [
        ...defaultHttpPorts,
        ...defaultHttpsPorts
    ].filter(port => formData.has(port.toString()));

    checkboxElements.forEach(elm => {
        form[elm.id] = formData.has(elm.id);
    });

    selectElements.forEach(elm => {
        let value = form[elm.id];
        if (value === 'true') value = true;
        if (value === 'false') value = false;
        form[elm.id] = value;
    });

    // 出站方式 (qj)：映射为 proxyOnly/proxyDegrade（对齐后端 qj 参数语义）
    // 下拉显示名：default=Default / only=Proxy Only / no=Direct Target（直连目标）
    const outboundMode = form.outboundMode || 'default';
    form.proxyOnly = outboundMode === 'only';
    form.proxyDegrade = outboundMode === 'no';
    delete form.outboundMode;

    inputElements.forEach(elm => {
        if (typeof form[elm.id] === 'string') {
            form[elm.id] = form[elm.id].trim();
        }
    });

    numInputElements.forEach(elm => {
        form[elm.id] = Number(form[elm.id].trim());
    });

    textareaElements.forEach(elm => {
        const key = elm.id;
        const value = form[key];
        let items = value?.split('\n').map(val => val.trim()).filter(Boolean) || [];
        if (['cleanIPs', 'proxyIPs', 'customCdnAddrs', 'hostSniList'].includes(key)) {
            items = items.flatMap(line => {
                if (line.includes(',') && !line.startsWith('#') && !line.startsWith('//')) {
                    return line.split(',').map(s => s.trim()).filter(Boolean);
                }
                return [line];
            });
            // 去重（保持先后顺序），URL 或普通条目归一化防重
            // 代理条目大小写敏感（user/pass、#备注），整体 toLowerCase 会静默改坏它们。
            const seen = new Set();
            items = items.filter(item => {
                const norm = (item.startsWith('http://') || item.startsWith('https://')) && !isProxyLikeEntry(item)
                    ? item.toLowerCase()
                    : item;
                if (seen.has(norm)) return false;
                seen.add(norm);
                return true;
            });
        }
        form[key] = items;
    });

    return form;
}

function logout(event) {
    event.preventDefault();
    fetch('/logout', { method: 'GET', credentials: 'same-origin' })
        .then(response => response.json())
        .then(({ success, status, message }) => {
            if (!success) {
                throw new Error(`status ${status} - ${message}`);
            }

            window.location.href = '/login';
        })
        .catch(error => console.error("Logout error:", error.message || error));
}

function resetPassword(event) {
    event.preventDefault();
    const resetPassModal = document.getElementById('resetPassModal');
    const newPasswordInput = document.getElementById('newPassword');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const passwordError = document.getElementById('passwordError');
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (newPassword !== confirmPassword) {
        passwordError.textContent = "Passwords do not match";
        return false;
    }

    const hasCapitalLetter = /[A-Z]/.test(newPassword);
    const hasNumber = /[0-9]/.test(newPassword);
    const isLongEnough = newPassword.length >= 8;

    if (!(hasCapitalLetter && hasNumber && isLongEnough)) {
        passwordError.textContent = '⚠️ Password must contain at least one capital letter, one number, and be at least 8 characters long.';
        return false;
    }

    fetch('/panel/reset-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'text/plain'
        },
        body: newPassword,
        credentials: 'same-origin'
    })
        .then(response => response.json())
        .then(({ success, status, message }) => {
            if (!success) {
                passwordError.textContent = `⚠️ ${message}`;
                throw new Error(`status ${status} - ${message}`);
            }

            alert("✅ Password changed successfully! 👍");
            window.location.href = '/login';

        })
        .catch(error => console.error("Reset password error:", error.message || error))
        .finally(() => {
            resetPassModal.style.display = "none";
            document.body.style.overflow = "";
        });
}

function renderPortsBlock(ports) {
    const totalPorts = [
        ...(window.origin.includes('workers.dev') ? defaultHttpPorts : []),
        ...defaultHttpsPorts
    ];

    // F21：端口来自 KV / 导入的 .dat，一律用 DOM API 构建（不再拼 innerHTML）；
    // 原先 TLS 端口的点击行为靠字符串内联 onclick 生成，现改为 addEventListener
    const tlsPortsContainer = document.getElementById("tls-ports");
    const noneTlsPortsContainer = document.getElementById("non-tls-ports");
    tlsPortsContainer.replaceChildren();
    noneTlsPortsContainer.replaceChildren();

    let noneTlsPortCount = 0;

    totalPorts.forEach(port => {
        const isTlsPort = defaultHttpsPorts.includes(port);
        const portBlock = document.createElement('div');
        portBlock.className = 'routing';

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.name = port;
        checkbox.value = 'true';
        checkbox.checked = ports.includes(port);

        if (isTlsPort) {
            checkbox.className = 'https';
            checkbox.addEventListener('click', handlePortChange);
        }

        const label = document.createElement('label');
        label.textContent = port;

        portBlock.append(checkbox, label);

        if (isTlsPort) {
            tlsPortsContainer.append(portBlock);
        } else {
            noneTlsPortsContainer.append(portBlock);
            noneTlsPortCount++;
        }
    });

    if (noneTlsPortCount) {
        document.getElementById("none-tls").style.display = 'flex';
    }
}

function addUdpNoise(isManual, noiseIndex, udpNoise) {
    const index = noiseIndex ?? globalThis.xrayNoiseCount;
    const noise = udpNoise || {
        type: 'rand',
        packet: '50-100',
        delay: '1-5',
        count: 5
    };

    const container = document.createElement('div');
    container.className = "inner-container";
    container.id = `udp-noise-${index + 1}`;

    // F21：noise 的 packet/type/delay/count 来自 KV / 导入的 .dat，
    // 原先拼进 innerHTML 的属性位（`value="${noise.packet}"`）可被 `"><img onerror=…>` 逃逸；
    // 现全部改为 textContent / value 赋值，不经过任何 HTML 解析
    const headerContainer = document.createElement('div');
    headerContainer.className = 'header-container';

    const noiseTitle = document.createElement('h4');
    noiseTitle.textContent = `Noise ${index + 1}`;

    const deleteButton = document.createElement('button');
    deleteButton.type = 'button';
    deleteButton.className = 'delete-noise';
    const deleteIcon = document.createElement('span');
    deleteIcon.className = 'material-symbols-rounded';
    deleteIcon.textContent = 'delete';
    deleteButton.append(deleteIcon);

    headerContainer.append(noiseTitle, deleteButton);

    const buildFormControl = labelText => {
        const formControl = document.createElement('div');
        formControl.className = 'form-control';

        const label = document.createElement('label');
        label.textContent = labelText;

        const wrapper = document.createElement('div');
        formControl.append(label, wrapper);

        return { formControl, wrapper };
    };

    const section = document.createElement('div');
    section.className = 'section';

    const modeControl = buildFormControl('😵‍💫 Mode');
    const modeSelect = document.createElement('select');
    modeSelect.name = 'udpXrayNoiseMode';
    [
        ['base64', 'Base64'],
        ['rand', 'Random'],
        ['str', 'String'],
        ['hex', 'Hex'],
        ['array', 'Array']
    ].forEach(([value, text]) => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = text;
        if (noise.type === value) option.selected = true;
        modeSelect.append(option);
    });
    modeControl.wrapper.append(modeSelect);

    const packetControl = buildFormControl('📦 Packet');
    const packetInput = document.createElement('input');
    packetInput.type = 'text';
    packetInput.name = 'udpXrayNoisePacket';
    packetInput.value = noise.packet;
    packetControl.wrapper.append(packetInput);

    const countControl = buildFormControl('🎚️ Count');
    const countInput = document.createElement('input');
    countInput.type = 'number';
    countInput.name = 'udpXrayNoiseCount';
    countInput.value = noise.count;
    countInput.min = '1';
    countInput.required = true;
    countControl.wrapper.append(countInput);

    const delayControl = buildFormControl('🕞 Delay');
    delayControl.wrapper.className = 'min-max';
    const delayMinInput = document.createElement('input');
    delayMinInput.type = 'number';
    delayMinInput.name = 'udpXrayNoiseDelayMin';
    delayMinInput.value = noise.delay.split('-')[0];
    delayMinInput.min = '1';
    delayMinInput.required = true;
    const delaySeparator = document.createElement('span');
    delaySeparator.textContent = ' - ';
    const delayMaxInput = document.createElement('input');
    delayMaxInput.type = 'number';
    delayMaxInput.name = 'udpXrayNoiseDelayMax';
    delayMaxInput.value = noise.delay.split('-')[1];
    delayMaxInput.min = '1';
    delayMaxInput.required = true;
    delayControl.wrapper.append(delayMinInput, delaySeparator, delayMaxInput);

    section.append(modeControl.formControl, packetControl.formControl, countControl.formControl, delayControl.formControl);

    container.append(headerContainer, section);

    container.querySelector(".delete-noise").addEventListener('click', deleteUdpNoise);
    container.querySelector("select").addEventListener('change', generateUdpNoise);

    document.getElementById("noises").append(container);
    if (isManual) enableApplyButton();
    globalThis.xrayNoiseCount++;
}

function generateUdpNoise(event) {
    const generateRandomBase64 = length => {
        const array = new Uint8Array(Math.ceil(length * 3 / 4));
        crypto.getRandomValues(array);
        let base64 = btoa(String.fromCharCode(...array));

        return base64.slice(0, length);
    }

    const generateRandomHex = length => {
        const array = new Uint8Array(Math.ceil(length / 2));
        crypto.getRandomValues(array);
        let hex = [...array].map(b => b.toString(16).padStart(2, '0')).join('');

        return hex.slice(0, length);
    }

    const generateRandomString = length => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const array = new Uint8Array(length);

        return Array.from(crypto.getRandomValues(array), x => chars[x % chars.length]).join('');
    };

    const noisePacket = event.target.closest(".inner-container").querySelector('[name="udpXrayNoisePacket"]');

    switch (event.target.value) {
        case 'base64':
            noisePacket.value = generateRandomBase64(64);
            break;

        case 'rand':
            noisePacket.value = "50-100";
            break;

        case 'hex':
            noisePacket.value = generateRandomHex(64);
            break;

        case 'str':
            noisePacket.value = generateRandomString(64);
            break;
    }
}

function deleteUdpNoise(event) {
    if (globalThis.xrayNoiseCount === 1) {
        alert('⛔ You cannot delete all noises!');
        return;
    }

    const confirmReset = confirm(
        '⚠️ This will delete the noise.\n\n' +
        '❓ Are you sure?'
    );

    if (!confirmReset) return;
    event.target.closest(".inner-container").remove();
    enableApplyButton();
    globalThis.xrayNoiseCount--;
}

function renderUdpNoiseBlock(xrayUdpNoises) {
    document.getElementById("noises").replaceChildren();
    xrayUdpNoises.forEach((noise, index) => {
        addUdpNoise(false, index, noise);
    });

    globalThis.xrayNoiseCount = xrayUdpNoises.length;
}

async function fetchSystemStatus() {
    try {
        const response = await fetch('/panel/region', { method: 'GET', credentials: 'include' });
        const { success, body } = await response.json();

        if (!success) return;

        const update = (id, val) => document.getElementById(id).textContent = val || '-';

        const effectiveRegion = body.wkRegion || body.resolvedProxyRegion || body.workerRegion;
        update('status-worker-region', effectiveRegion);
        update('status-cf-edge', body.workerColo);
        update('status-cf-country', body.workerRegion);
        update('status-your-ip', body.clientIP);
        update('status-your-country', body.clientCountry || '-');
        update('status-wk-region', body.wkRegion || body.resolvedProxyRegion || '(detected)');

        const regionMatch = document.getElementById('regionMatch')?.value === 'true';
        const isOfficialDirect = !body.wkRegion;
        const regionMatchEl = document.getElementById('status-region-match');
        if (isOfficialDirect) {
            update('status-region-match', '❌ Disabled(Official Direct)');
            regionMatchEl.style.opacity = '0.45';
        } else {
            update('status-region-match', regionMatch ? '✅ Enabled' : 'Disabled');
            regionMatchEl.style.opacity = '';
        }

        const echSelect = document.getElementById('enableECH');
        const echEnabled = echSelect?.value === 'true';
        const echServerName = document.getElementById('echServerName')?.value?.trim();
        update('status-ech', echEnabled
            ? (echServerName ? `✅ ${echServerName.split('\n')[0]}` : '✅ On')
            : '❌ Off');
    } catch (error) {
        console.error("System status fetch error:", error.message || error);
    }
}

// Auto-refresh every 30 seconds：只有首屏初始化成功（globalThis.panelReady）才轮询，
// 否则会话失效时会对着 /panel/region 每 30 秒白打一次请求
setInterval(() => {
    if (globalThis.panelReady) fetchSystemStatus();
}, 30000);