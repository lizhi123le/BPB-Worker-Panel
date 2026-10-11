import { SignJWT, jwtVerify } from 'jose';
import { HttpStatus, respond } from '@common';
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

    let secretKey = await env.kv.get('secretKey');

    if (!secretKey) {
        secretKey = generateSecretKey();
        await env.kv.put('secretKey', secretKey);
    }

    const secret = new TextEncoder().encode(secretKey);
    const { userID } = globalThis.globalConfig;

    const jwtToken = await new SignJWT({ userID })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS)
        .sign(secret);

    return respond(true, HttpStatus.OK, 'Successfully generated Auth token', null, {
        'Set-Cookie': `jwtToken=${jwtToken}; HttpOnly; Secure; Max-Age=${SESSION_TTL_SECONDS}; Path=/; SameSite=Strict`,
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
        console.log(error);
        return false;
    }
}

export async function resetPassword(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'POST') {
        return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'Method not allowed.');
    }

    let auth = await Authenticate(request, env);
    const oldPwd = await env.kv.get('pwd');

    if (oldPwd && !auth) {
        return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized.');
    }

    const newPwd = await request.text();
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
        'Set-Cookie': 'jwtToken=; Path=/; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'Content-Type': 'text/plain',
    });
}