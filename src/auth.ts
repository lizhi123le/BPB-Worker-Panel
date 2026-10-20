import { SignJWT, jwtVerify } from 'jose';
import { HttpStatus, isKvBound, respond, safeErrorMessage } from '@common';
import { checkAuthRateLimit, recordAuthFailure, resetAuthRateLimit } from './common/ratelimit';

/** 会话生命周期（秒）：JWT 过期时间与 Cookie Max-Age 必须同源，否则浏览器会拿着已过期令牌反复请求（F9） */
const SESSION_TTL_SECONDS = 24 * 60 * 60;

/** 口令比较（常量时间）：长度差与逐字符差累积进一个数值，循环次数不随比较结果提前退出 */
function constantTimeEqual(a: string, b: string): boolean {
    const len = Math.max(a.length, b.length);
    let diff = a.length ^ b.length;
    for (let i = 0; i < len; i++) {
        diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    }
    return diff === 0;
}

/** 会话 Cookie 头：属性与 JWT 的 TTL 同源（HttpOnly / Secure / SameSite=Strict），登录与首访设置口令共用 */
function sessionCookieHeader(token: string): string {
    return `jwtToken=${token}; HttpOnly; Secure; Max-Age=${SESSION_TTL_SECONDS}; Path=/; SameSite=Strict`;
}

/**
 * 清会话 Cookie（登出 / 改密吊销共用一份）。
 * 删除只认 name + domain + path，属性本身不影响删除结果；但属性与签发时（sessionCookieHeader）
 * 不一致会让浏览器与审计工具看到两种"登出"语义 —— F19 就是这条（旧值缺 HttpOnly 且 SameSite=None）。
 * 原先改密处还各写了一份更弱的字符串，现合并到这里。
 */
export function clearSessionCookieHeader(): string {
    return 'jwtToken=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
}

/**
 * 签发会话令牌。KV 里没有签名密钥时先生成一把：缺失只说明本部署还没签发过会话，不是登录失败。
 * 注意 setIssuedAt() 走的是 `new Date()`，所以过期时间必须与 SESSION_TTL_SECONDS 同源。
 */
async function issueSessionToken(env: Env): Promise<string> {
    let secretKey = await env.kv.get('secretKey');

    if (!secretKey) {
        secretKey = generateSecretKey();
        await env.kv.put('secretKey', secretKey);
    }

    const secret = new TextEncoder().encode(secretKey);
    const { userID } = globalThis.globalConfig;

    return await new SignJWT({ userID })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS)
        .sign(secret);
}

export async function generateJWTToken(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'POST') {
        return respond(false, 405, 'Method not allowed.');
    }

    const ip = request.headers.get('CF-Connecting-IP') || '';

    // 认证限流：超限不返回 429、不暴露限流特征，仍返回同样 401 但固定延迟。
    // 顺序很重要：必须排在读取 KV 之前。否则已被限流的爆破请求仍会逐次消耗 kv.get('pwd')
    // 的读额度——限流只挡住「继续试密码」，却挡不住「继续烧 KV 读」。超限后这里直接返回，0 次 KV 读。
    if (!checkAuthRateLimit(ip)) {
        console.warn(`[认证限流] IP ${ip} 登录失败次数超限`);
        await new Promise(r => setTimeout(r, 1500));
        return respond(false, HttpStatus.UNAUTHORIZED, 'Wrong password.');
    }

    const password = await request.text();
    const savedPass = await env.kv.get('pwd');

    if (savedPass === null || !constantTimeEqual(password, savedPass)) {
        recordAuthFailure(ip);
        return respond(false, HttpStatus.UNAUTHORIZED, 'Wrong password.');
    }

    resetAuthRateLimit(ip);

    const jwtToken = await issueSessionToken(env);

    return respond(true, HttpStatus.OK, 'Successfully generated Auth token', null, {
        'Set-Cookie': sessionCookieHeader(jwtToken),
        'Content-Type': 'text/plain',
    });
}

/**
 * 首访设置管理员口令（POST /login/set-password）：KV 里还没有 `pwd` 时允许未登录调用，
 * 设置成功后直接签发会话（前端不用再走一次 /login/authenticate）。
 *
 * 与 resetPassword 的分工：这里是**唯一**的「未登录写入口令」路径 ——
 * resetPassword 只管已登录改密（会清 Cookie 并轮换签名密钥），两条路都不会覆盖已有口令。
 *
 * 本路径豁免了 initHttp 的 KV 校验（/login 要能在没绑 KV 时打开），所以必须自己判 KV：
 * 否则 env.kv.get 的 TypeError 会冒泡成 HTML 错误页，前端拿不到 success/message 字段，
 * 「还没绑 KV」这件事就永远提示不出来。
 */
export async function initializePassword(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'POST') {
        return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'Method not allowed.');
    }

    if (!isKvBound(env)) {
        console.warn('[首访设置口令] KV 未绑定，管理员口令无法保存');
        return respond(
            false,
            HttpStatus.INTERNAL_SERVER_ERROR,
            'KV namespace is not bound, so the administrator password can not be saved. Bind a KV namespace to this Worker with the variable name "kv" (lowercase), then try again.',
        );
    }

    const ip = request.headers.get('CF-Connecting-IP') || '';

    // 顺序与 generateJWTToken 一致：限流判定排在一切 KV 读之前（超限时 0 次 KV 读）
    if (!checkAuthRateLimit(ip)) {
        console.warn(`[认证限流] IP ${ip} 首访设置口令请求超限`);
        await new Promise(r => setTimeout(r, 1500));
        return respond(false, HttpStatus.UNAUTHORIZED, 'Too many failed attempts. Please try again later.');
    }

    if ((await env.kv.get('pwd')) !== null) {
        // 已经设过口令：与「猜口令失败」记同一本账，但错误信息明确指向登录（前端据此切回登录表单）
        recordAuthFailure(ip);
        return respond(false, HttpStatus.UNAUTHORIZED, 'Administrator password is already set. Please log in.');
    }

    const newPassword = await request.text();

    // 空口令必须在这里挡住：pwd 一旦落成空串，「空口令 = 正确口令」会让面板对任何人敞开
    if (!newPassword) {
        return respond(false, HttpStatus.BAD_REQUEST, 'Password can not be empty.');
    }

    await env.kv.put('pwd', newPassword);

    // 设置成功即视为一次成功认证：清掉本 IP 之前攒下的失败计数（例如拿着过期页面反复重试）
    resetAuthRateLimit(ip);

    const jwtToken = await issueSessionToken(env);

    return respond(true, HttpStatus.OK, 'Administrator password set successfully.', null, {
        'Set-Cookie': sessionCookieHeader(jwtToken),
        'Content-Type': 'text/plain',
    });
}

function generateSecretKey(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);

    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function Authenticate(request: Request, env: Env): Promise<boolean> {
    try {
        // KV 未绑定（登录页首访流程允许这种部署打开页面）时先短路：不短路的话
        // `env.kv.get` 会抛 TypeError 被这里的 catch 吞掉，日志里留下一段与真实原因无关的堆栈。
        if (!isKvBound(env)) {
            console.log('KV is not bound, authentication skipped.');
            return false;
        }

        const secretKey = await env.kv.get('secretKey');

        if (secretKey === null) {
            console.log("Secret key not found in KV.");
            return false;
        }

        const secret = new TextEncoder().encode(secretKey);
        const cookie = request.headers.get('Cookie')?.match(/(^|;\s*)jwtToken=([^;]*)/);
        const token = cookie ? cookie[2] : null;

        if (!token) {
            console.log('Unauthorized: Token not available!');
            return false;
        }

        const { payload } = await jwtVerify(token, secret);
        console.log(`Successfully authenticated, User ID: ${payload.userID}`);

        return true;
    } catch (error) {
        // 只留一行原因，**不要**打整个 Error：这条路径对任何携带伪造/过期 jwtToken 的请求都会走到
        // （/panel/* 在鉴权前就可达），打 Error 会把完整堆栈写进 Worker 日志 —— 一个 Cookie 就能灌日志。
        // jose 验签失败带 code（如 ERR_JWS_SIGNATURE_VERIFICATION_FAILED），优先用它，便于日志检索。
        console.log(`Authentication failed: ${(error as { code?: string })?.code || safeErrorMessage(error)}`);
        return false;
    }
}

/**
 * 管理接口统一会话守卫（auth.ts 与 handlers.ts 共用）：
 * 先校验 HTTP 方法（可选），再校验会话。返回 Response 表示应直接结束请求；null 表示通过。
 * 此前每个管理接口都手写一份「405 + 401」判断，漏改一处就会出现鉴权语义分叉。
 * 两条文案可按调用点覆盖，保证合并后响应体与既有接口逐字一致。
 */
export async function requireSession(
    request: Request,
    env: Env,
    options: { method?: string; unauthorizedMessage?: string; methodMessage?: string } = {}
): Promise<Response | null> {
    const {
        method,
        unauthorizedMessage = 'Unauthorized or expired session.',
        methodMessage = 'Method not allowed.'
    } = options;

    if (method && request.method !== method) {
        return respond(false, HttpStatus.METHOD_NOT_ALLOWED, methodMessage);
    }

    if (!(await Authenticate(request, env))) {
        return respond(false, HttpStatus.UNAUTHORIZED, unauthorizedMessage);
    }

    return null;
}

export async function resetPassword(request: Request, env: Env): Promise<Response> {
    // 只服务「已登录改密」。这里曾经在「KV 尚无 pwd」时免鉴权放行（面板首访弹窗走的就是那条路），
    // 首访入口收敛到 /login/set-password 之后它就是冗余的第二条「未登录抢设口令」路径，故去掉。
    const denied = await requireSession(request, env, { method: 'POST', unauthorizedMessage: 'Unauthorized.' });
    if (denied) return denied;

    const oldPwd = await env.kv.get('pwd');
    const newPwd = await request.text();

    // 与 /login/set-password 同一道兜底：pwd 落成空串等于「空口令即可登录」
    if (!newPwd) {
        return respond(false, HttpStatus.BAD_REQUEST, 'Password can not be empty.');
    }

    if (newPwd === oldPwd) {
        return respond(false, HttpStatus.BAD_REQUEST, 'Please enter a new Password.');
    }

    await env.kv.put('pwd', newPwd);

    // 会话吊销（F9）：轮换签名密钥 —— 服务端没有「已签发令牌」清单，
    // 唯一可靠的撤回手段就是让旧密钥签发的令牌验不过（无 jti，也不新增任何 KV 读）。
    // 代价：所有已登录设备（含本次改密的这一台）立即登出 —— 这是「改密即真正吊销」的应有代价，不是缺陷。
    // 登录流程不受影响：generateJWTToken 会重读 secretKey，缺失时重新生成并签发新令牌，下一次登录即生效。
    await env.kv.put('secretKey', generateSecretKey());

    return respond(true, HttpStatus.OK, 'Password reset successfully.', null, {
        'Set-Cookie': clearSessionCookieHeader(),
        'Content-Type': 'text/plain',
    });
}