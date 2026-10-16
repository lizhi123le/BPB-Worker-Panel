// 背景 iframe:URL 池随机(带随机 query 绕过缓存,每次刷新换背景)
(function initFallbackBg() {
    const bg = document.getElementById('fallback-bg');
    if (bg) {
        bg.src = '/img?t=' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    }
})();

const loginForm = document.getElementById('loginForm');
const setupForm = document.getElementById('setupForm');
const passwordError = document.getElementById('passwordError');
const setupError = document.getElementById('setupError');

/**
 * 首访引导：服务端在 KV 尚无管理员口令时把 __AUTH_MODE__ 换成 setup —— 此时给「设置管理员口令」表单，
 * 而不是让用户去猜一个还不存在的口令（原行为：怎么输都 401 Wrong password）。
 * 这个标记只是界面开关：真正允许「未登录写入口令」的是 /login/set-password（仅在 pwd 为空时放行），
 * 所以标记过期（页面打开期间口令已被设走）只会退化成一次 401，不会越权覆盖口令。
 *
 * 两种模式的切换只在这里写标记 / 标题 / 错误提示：两张表单的显隐由 body[data-auth-mode] + CSS 决定
 * （CSS 在 </head>、脚本在 </body> 前，用 JS 切显隐会先闪一下错的那张）。
 */
function applyMode(mode, errorText) {
    const isSetup = mode === 'setup';
    document.body.dataset.authMode = isSetup ? 'setup' : 'login';
    document.getElementById('formTitle').textContent = isSetup ? 'Set Administrator Password' : 'User Login';
    document.title = isSetup ? 'Set Administrator Password' : 'Login';
    passwordError.textContent = errorText || '';
}

/**
 * 读 JSON 结果。服务端在「部署没配好」（缺 UUID / Trojan 口令、KV 未绑定、内部异常）时
 * 回的是 HTML 错误页，直接 response.json() 只会抛 `Unexpected token '<'` 这种看不出所以然的天书，
 * 这里统一转成一句能照做的提示（KV 绑定是部署最常见的漏配项，所以提示里点名它），
 * 并用 unexpected 标记区分「服务端明确拒绝」与「根本没拿到 JSON」。
 */
async function readResult(response) {
    try {
        return await response.json();
    } catch {
        return {
            success: false,
            unexpected: true,
            status: response.status,
            message: `Unexpected server response (HTTP ${response.status}). Bind a KV namespace with the variable name "kv" (lowercase), and make sure the UUID / Trojan password are set.`
        };
    }
}

// 初始模式由服务端标记决定（setup / login）
applyMode(document.body.dataset.authMode);

loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/login/authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain'
            },
            body: password
        });

        const { success, status, message, unexpected } = await readResult(response);
        if (!success) {
            // 只有「服务端明确判定口令不对」才说 Wrong Password；没拿到 JSON 时如实转述服务端提示
            passwordError.textContent = unexpected ? `⚠️ ${message}` : '⚠️ Wrong Password!';
            throw new Error(`Login failed with status ${status}: ${message}`);
        }

        window.location.href = '/panel';
    } catch (error) {
        console.error('Login error:', error.message || error);
    }
});

setupForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const submitButton = setupForm.querySelector('button[type="submit"]');

    setupError.textContent = '';

    if (newPassword !== confirmPassword) {
        setupError.textContent = '⚠️ Passwords do not match.';
        return;
    }

    // 强度规则与面板「修改口令」弹窗逐字一致；服务端不校验强度（只管 pwd 是否已存在），
    // 所以这里是唯一的把关点，改动时两边要一起改。
    if (!(/[A-Z]/.test(newPassword) && /[0-9]/.test(newPassword) && newPassword.length >= 8)) {
        setupError.textContent = '⚠️ Password must contain at least one capital letter, one number, and be at least 8 characters long.';
        return;
    }

    submitButton.disabled = true;

    try {
        // /login/set-password：KV 里还没有 pwd 时才放行，成功即签发会话，不需要再走一次登录。
        // KV 未绑定时它回的是可读 JSON（"KV namespace is not bound, ..."），原样显示给用户即可，
        // 用户绑好 KV 后不用刷新页面，直接再点一次就能设置成功。
        const response = await fetch('/login/set-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain'
            },
            body: newPassword
        });
        const { success, status, message } = await readResult(response);

        if (!success) {
            // 401 = 打开页面之后口令已经被设走了：退回登录表单，不再尝试覆盖别人的口令
            if (status === 401) {
                applyMode('login', `⚠️ ${message}`);
                return;
            }
            setupError.textContent = `⚠️ ${message}`;
            console.error(`Set password failed with status ${status}: ${message}`);
            return;
        }

        window.location.href = '/panel';
    } catch (error) {
        setupError.textContent = `⚠️ ${error.message || error}`;
        console.error('Set password error:', error.message || error);
    } finally {
        submitButton.disabled = false;
    }
});

// 两个表单里的眼睛图标行为一致：切换前一个兄弟节点（input）的 type。
// 图标语义 = 当前状态（初始 markup 就是密码隐藏态的 visibility_off）：
// 切到明文显示「睁眼 visibility」，切回密码显示「斜杠眼 visibility_off」—— 与面板脚本同一套约定。
document.querySelectorAll('.toggle-password').forEach((toggle) => {
    toggle.addEventListener('click', function () {
        const input = this.previousElementSibling;
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        this.textContent = isPassword ? 'visibility' : 'visibility_off';
    });
});
