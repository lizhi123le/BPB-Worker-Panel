interface WarpKeys {
    publicKey: string;
    privateKey: string;
}

const defaultWarpAccounts: WarpAccount[] = [    {
        privateKey: "sBmQVHEywGAKQ8Ratzo/f5OUCa7MSozZpz1JK2PSVXE=",
        publicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        warpIPv6: "2606:4700:110:8dd8:de5f:9a89:bfac:749c/128",
        reserved: "59nK"
    },
    {
        privateKey: "OPiD4dePq8652DICknJsTJS4UH0FoWY1ffOZzZhIsUs=",
        publicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        warpIPv6: "2606:4700:110:8912:1225:70c8:1ad7:6ce0/128",
        reserved: "G/nh"
    }
];

/**
 * B-02：内置兜底账号必须**导出** —— 失败路径要用「不写 KV、直接用内置账号」，
 * 而 getDataset 需要拿到这份数据源才能跳过 fetchWarpAccounts。
 *
 * 注意这份账号是源码内的**公共身份**：所有注册失败的部署共享同一 WARP 身份。
 * 因此它只应作为临时兜底，不能落进 KV（落进去就等于永久接管，见 kv.ts 的注释）。
 */
export const DEFAULT_WARP_ACCOUNTS: readonly WarpAccount[] = defaultWarpAccounts;

/** 注册结果：`fallback === true` 表示走的是内置兜底账号，调用方据此决定是否写失败标记 / 报错 */
export interface WarpAccountsResult {
    accounts: WarpAccount[];
    fallback: boolean;
}

export async function fetchWarpAccounts(env: Env): Promise<WarpAccountsResult> {
    const warpAccounts: WarpAccount[] = [];

    try {

        const warpKeys = [
            await generateKeyPair(),
            await generateKeyPair()
        ];

        for (const [index, key] of warpKeys.entries()) {
            const { config } = await fetchAccount(key);

            // 上游字段守卫：client_id 缺失/为空时 reserved 会以 undefined 落进 KV（JSON 序列化丢键），
            // 下游只会得到一个空 reserved。此处直接抛错，由外层 catch 回退到内置默认账号。
            // （interface.addresses.v6 / peers[0].public_key 缺失会在下方取用时抛 TypeError，同样落入该 catch）
            if (typeof config?.client_id !== 'string' || config.client_id.length === 0) {
                throw new Error('WARP registration response is missing a valid client_id (reserved).');
            }

            warpAccounts.push({
                privateKey: key.privateKey,
                warpIPv6: `${config.interface.addresses.v6}/128`,
                reserved: config.client_id,
                publicKey: config.peers[0].public_key
            });

            if (index === 0) await new Promise(resolve => setTimeout(resolve, 1000));
        }

        await env.kv.put('warpAccounts', JSON.stringify(warpAccounts));
        return { accounts: warpAccounts, fallback: false };

    } catch (error) {
        console.error(
            'Failed to fetch new WARP accounts:', 
            error instanceof Error ? error.message : String(error)
        );

        // B-02：**不要**在这里 put 内置账号。kv.ts 的重新注册条件是「KV 里没有有效账号」，
        // 而内置账号两条都形状合法 → 一旦落库就再也不会重试，把「每条连接重试」换成
        // 「永远不重试」。失败标记由调用方写（见 kv.ts 的 warpAccountsStaleAt）。
        return { accounts: [...defaultWarpAccounts], fallback: true };
    }
}

async function fetchAccount(key: WarpKeys): Promise<any> {
    const response = await fetch('https://api.cloudflareclient.com/v0a4005/reg', {
        method: 'POST',
        // B-02：注册请求必须自带超时。原实现没有 signal —— 上游「收下连接但不回包」时
        // 会一直挂到平台 fetch 超时才失败，而这条路径在失败后仍是每条连接都要重走一次。
        signal: AbortSignal.timeout(8000),
        headers: {
            'User-Agent': 'insomnia/8.6.1',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            install_id: "",
            fcm_token: "",
            tos: new Date().toISOString(),
            type: "Android",
            model: 'PC',
            locale: 'en_US',
            warp_enabled: true,
            key: key.publicKey
        })
    });

    if (!response.ok) {
        throw new Error(`API returned status ${response.status}: ${await response.text()}`);
    }

    return response.json();
}

async function generateKeyPair(): Promise<WarpKeys> {
    const keyPair = await crypto.subtle.generateKey(
        { name: "X25519", namedCurve: "X25519" },
        true,
        ["deriveBits"]
    );

    const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateKeyRaw = new Uint8Array(pkcs8).slice(-32);

    const publicKeyRaw = new Uint8Array(
        await crypto.subtle.exportKey("raw", keyPair.publicKey)
    );

    const base64Encode = (arr: Uint8Array) => btoa(String.fromCharCode(...arr));

    return {
        publicKey: base64Encode(publicKeyRaw),
        privateKey: base64Encode(privateKeyRaw)
    };
}