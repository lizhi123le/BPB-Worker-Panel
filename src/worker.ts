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
import { isBuiltinRouteWord, isPathInDictionary, PUBLIC_PATH_POOL } from './common/ratelimit';
import { camouflageProxy, cf1101RateLimitedResponse } from './common/camouflage';
import { prepareWsRuntimeConfig } from './common/ws-runtime';
import { handleXhttp } from '@protocols/xhttp/handler';

/** 伪装路径池（字典剔除内置路由词后的结果）转成 Set：XHTTP 判定在热路径上，逐段 includes 太慢 */
const XHTTP_CAMOUFLAGE_PATH_POOL: ReadonlySet<string> = new Set(PUBLIC_PATH_POOL);

/**
 * XHTTP 入站的路径白名单。
 *
 * 为什么需要白名单：XHTTP 只按「POST + 开关」接线，若不加路径限制，既有 POST 路由会被它整条吞掉。
 * 判定顺序：
 *  1. 首段命中内置路由词 → 直接否。不能只靠「词不在路径字典里」这条**当前数据**的巧合：
 *     BUILTIN_ROUTE_WORDS 的存在说明这些词将来可能被回填进限流字典，一旦回填，
 *     `POST /panel/...`、`POST /login/...` 就会被 XHTTP 接管，面板/登录直接坏掉。
 *  2. 根路径 `/`：关闭「节点随机路径」时 XHTTP 节点就走 `/`（与 WS 的 `/?ed=…` 同形态）；
 *  3. 管理员路径（env.SUB_PATH 或 UUID）：手工把节点路径设成订阅/UUID 路径的旧配置；
 *  4. UUID 前 8 位：对齐参考实现的 `/{uuid.slice(0,8)}` 形态。本订阅不会主动生成它
 *     （避免 UUID 片段进 URL），但放行成本为零、能兼容手写配置；
 *  5. 每一段都在**伪装路径池**内（PUBLIC_PATH_POOL，已剔除内置路由词）：订阅随机路径正是从这里抽的。
 *     用池而不是 PUBLIC_PATH_DICTIONARY，语义上就是「只接受订阅可能生成的路径」。
 * 另外把连续斜杠归一后再判，避免 `//panel` 之类的变体绕过首段比较。
 */
function isXhttpPathAllowed(pathSegments: string[], adminPath: string, userID: string): boolean {
	const segments = pathSegments.flatMap(segment => segment.split('/')).filter(Boolean);

	// 根路径没有首段，必须放在内置词判定之前（空段数组交给它会把 `/` 判错）
	if (segments.length === 0) return true;

	const first = segments[0].toLowerCase();
	if (isBuiltinRouteWord(first)) return false;
	if (adminPath && first === adminPath) return true;
	if (userID && first === userID.slice(0, 8).toLowerCase()) return true;
	return segments.every(segment => XHTTP_CAMOUFLAGE_PATH_POOL.has(segment));
}

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
					return await cf1101RateLimitedResponse(wsUrl.host, request.headers.get('CF-Connecting-IP') || '');
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

				// ===== XHTTP 入站（POST / stream-one）=====
				// 必须放在路径 switch 之前：XHTTP 节点路径可能就是 `/` 或伪装路径池里的路径，
				// 这些在 HTTP 分支里本来会落到伪装页 / 伪装反代；只有三条同时成立才接管，
				// /panel、/login、/sub 等既有 POST 路由与伪装逻辑完全不受影响。
				//
				// 判定顺序（与任务书给的顺序有一处必要的调整）：先做零成本的白名单，
				// 再 initWs + setSettings 读 KV，最后才看 xhttpConfigs 开关。
				// 原因是冷 isolate 的 globalThis.settings 还是出厂默认（xhttpConfigs=false），
				// 若先读开关，isolate 的第一个 XHTTP 请求必然落回伪装页，表现为「XHTTP 时好时坏」。
				if (request.method === 'POST') {
					const xhttpSegments = pathName.split('/').filter(Boolean);
					const xhttpAdminPath = String((env as any).SUB_PATH || globalThis.globalConfig.userID || '')
						.toLowerCase()
						.replace(/^\//, '');
					if (isXhttpPathAllowed(xhttpSegments, xhttpAdminPath, globalThis.globalConfig.userID || '')) {
						initWs(env);
						await setSettings(request, env);
						if (globalThis.settings?.xhttpConfigs === true) {
							// 出站策略与 WS 共用同一份推导（反代池 / 官方池 / 地区 / 出站模式），
							// 两条入站必须看到同一份 wsConfig，否则出口行为会不一致。
							await prepareWsRuntimeConfig(request, env);
							return await handleXhttp(request, env);
						}
					}
				}

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
