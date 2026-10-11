import { init, initHttp, initWs, setSettings, assertRequiredCredentials } from '@init';
import {
	fallback,
	serveIcon,
	renderSecrets,
	handlePanel,
	handleSubscriptions,
	handleLogin,
	logout,
	renderError,
	handleWebsocket,
	handleDoH,
	handleProxyIPs
} from '@handlers';
import { guardNonBuiltinPath, guardWebsocketBlacklist } from './common/firstCheck';
import { isPathInDictionary } from './common/ratelimit';
import { camouflageProxy, cf1101Page } from './common/camouflage';

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		try {
			// 挂到全局，供伪装反代 / 限流 / 黑名单读取（对齐 cfnew 的 执行上下文 语义）
			(globalThis as any).env = env;
			(globalThis as any).ctx = ctx;

			// F-13：Upgrade 头值大小写不敏感（RFC 7230），客户端发 `Upgrade: WebSocket` 时
			// 原先的小写精确比较会把它判成普通 HTTP 请求 → 掉进伪装分支，WS 连不上且无提示
			const upgradeHeader = request.headers.get('Upgrade')?.toLowerCase();
			init(request, env);

			if (upgradeHeader === 'websocket') {
				// H5：WS 分支此前完全绕过守卫，任何路径都能稳定拿到 101。
				// 现在的顺序：永久黑名单（H5）→ 路径字典（F-22）→ 必填凭据（C-13）→ handleWebsocket。
				const wsGuarded = await guardWebsocketBlacklist(request, env);
				if (wsGuarded) return wsGuarded;

				// F-22（H5 剩余项）：黑名单之外再补路径字典校验 —— 与 HTTP 非内置路径同一判据。
				// 注意 firstCheck.ts 里 guardWebsocketBlacklist 上方「不加字典校验」的注释是 H5 当时的结论，
				// F-22 已裁决推翻它（仅就字典校验而言），该注释待后续单独更新。
				// 只补字典校验、不补限流：每一次 WS 连接（含客户端断线自动重连）都是一个请求，
				// 套用「6 次/小时」的路径限流会直接打死自己的客户端（见 guardWebsocketBlacklist 注释）。
				// 另：WS 分支无法按「已认证连接豁免」—— 认证要等首包，101 之前拿不到身份。
				// 两类豁免都不能误杀：根路径（旧订阅的 `/?ed=2560` 形态）与管理员路径
				// （用户手工把 WS 路径设成 SUB_PATH / UUID 的旧配置）。
				const wsUrl = new URL(request.url);
				const { pathName: wsPathName } = globalThis.globalConfig;
				const wsSegments = wsPathName.split('/').filter(Boolean);
				const wsAdminPath = String((env as any).SUB_PATH || (globalThis as any).globalConfig?.userID || '')
					.toLowerCase()
					.replace(/^\//, '');
				const wsPathAllowed = wsSegments.length === 0
					|| !!(wsAdminPath && wsSegments[0].toLowerCase() === wsAdminPath)
					|| isPathInDictionary(wsSegments);
				if (!wsPathAllowed) {
					console.warn(`[路径字典] WS 升级路径 ${wsPathName} 不在公共路径字典内，按伪造探测拦截`);
					return new Response(await cf1101Page(wsUrl.host, request.headers.get('CF-Connecting-IP') || ''), {
						status: 429,
						headers: {
							'Content-Type': 'text/html; charset=UTF-8',
							'Retry-After': '3600'
						}
					});
				}

				// C-13：与 HTTP 路径共用同一套必填凭据校验（此前 WS 完全跳过，缺凭据时静默鉴权失败）
				assertRequiredCredentials(env, wsPathName);

				initWs(env);
				await setSettings(request, env);
				return await handleWebsocket(request, env);
			} else {
				await initHttp(request, env);
				const { pathName } = globalThis.globalConfig;
				const path = pathName.split('/')[1];

				switch (path) {
					case 'panel':
						return await handlePanel(request, env);

					case 'sub':
						return await handleSubscriptions(request, env);

					case 'login':
						return await handleLogin(request, env);

					case 'logout':
						return await logout();

					case 'secrets':
						return await renderSecrets();

					case 'favicon.ico':
						return await serveIcon();

					case 'dns-query':
						return await handleDoH(request);

					case 'proxy-ip':
						return await handleProxyIPs(request, env);

					default:
						// 根路径 /：从设置的 URL 伪装地址池随机抽一个，图片则全屏拉伸显示
						if (pathName === '/' || pathName === '') {
							return await camouflageProxy(request, env);
						}
						// 非内置路径：永久黑名单 → 限流 → 全路径伪装反代（对齐 cfnew）
						const guarded = await guardNonBuiltinPath(request, env, ctx);
						if (guarded) return guarded;
						return await fallback(request);
				}
			}
		} catch (error) {
			return await renderError(error);
		}
	}
}
