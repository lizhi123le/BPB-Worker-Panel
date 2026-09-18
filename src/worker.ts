import { init, initHttp, initWs, setSettings } from '@init';
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
import { guardNonBuiltinPath } from './common/firstCheck';
import { camouflageProxy } from './common/camouflage';

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		try {
			// 挂到全局，供伪装反代 / 限流 / 黑名单读取（对齐 cfnew 的 执行上下文 语义）
			(globalThis as any).env = env;
			(globalThis as any).ctx = ctx;

			const upgradeHeader = request.headers.get('Upgrade');
			init(request, env);

			if (upgradeHeader === 'websocket') {
				initWs(env);
				await setSettings(request, env);
				return await handleWebsocket(request, env);
			} else {
				initHttp(request, env);
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
