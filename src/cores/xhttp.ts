import { generateWsPath, getXPaddingIdentifier } from '@utils';

/**
 * XHTTP 传输模式。
 *
 * 固定用 `stream-one`：同一个 HTTP POST 流同时承载上行与下行，是 Xray / mihomo 等内核
 * 支持度最广、语义最简单的一档。`packet-up` / `stream-up` 需要额外的流映射与多请求拼装，
 * worker 侧的 XHTTP 入站也没有实现这些分支，写进订阅会得到连不上的节点，因此不做可配置。
 */
export const XHTTP_MODE = 'stream-one';

/**
 * 订阅侧 XHTTP 节点的路径。
 *
 * 为什么规则是这样：
 * - worker 的 XHTTP 入站**不校验**路径的字面值（只按 HTTP 方法 + 路径白名单判定），
 *   根路径 `/` 与 uuid 前 8 位都在白名单里，所以路径在这里纯粹是伪装面，不承担协议功能；
 * - 「节点随机路径」开启时直接复用 WS 的随机字典路径：一方面让同一份订阅里两种传输的
 *   路径呈现同一类人类可读形态，另一方面与 WS 节点**共用同一个 usedPaths 集合**，
 *   从而保证同一次生成中任意两个节点的路径互不相同（跨传输也不撞车）；
 * - 关闭随机路径时收敛到根路径 `/`，与 WS 关闭态（`/?ed=…` 的根路径形态）保持一致，
 *   并且不把 UUID 片段暴露在 URL 里 —— 参考实现用的是 `/${uuid.slice(0, 8)}`，
 *   那会把 8 个 UUID 字符写进可被旁观者收集的请求路径，本实现刻意不这么做，
 *   服务端白名单两种都放行，功能上无差别。
 *
 * @param randomPath 面板「节点随机路径」开关（settings.randomPath）的当前值
 * @param usedPaths  同一次生成中的已占用路径集合，与 WS 节点共享；开启随机路径时才写入
 */
export function buildXhttpNodePath(randomPath: boolean, usedPaths?: Set<string>): string {
    // 关闭随机路径：统一根路径，且不占用 usedPaths（与 generateWsPath 关闭态语义一致，
    // 否则会把 '/' 也标记为已占用，虽然无实际影响但语义上不该参与去重）。
    if (!randomPath) return '/';

    // 开启随机路径：交给 WS 同一个生成器，共用 usedPaths 保证跨节点、跨传输唯一。
    // 该函数自身也兜底了 settings.randomPath === false 的情况（返回 '/'），不会抛错。
    return generateWsPath(usedPaths);
}

/**
 * xPadding 伪装参数（XHTTP 抗指纹填充的约定对象）。
 *
 * 单一来源：raw URI 的 `extra` 参数与 xray JSON 的 `streamSettings.xhttpSettings.extra`
 * 必须逐字一致，否则同一份订阅在两类客户端上会填出不同的头名 / 键名，特征反而更显眼；
 * worker 的 XHTTP 入站也按同一份派生规则识别（`@utils#getXPaddingIdentifier`）。
 *
 * 头名 / 键名不写死、按 UUID 派生：固定字符串是最容易被指纹化的常量，
 * 而派生规则两端共享，既做到每个部署不同，又不引入额外配置项。
 */
export function buildXhttpExtra(userID: string): {
    xPaddingObfsMode: true;
    xPaddingMethod: 'tokenish';
    xPaddingPlacement: 'queryInHeader';
    xPaddingHeader: string;
    xPaddingKey: string;
} {
    const { header, key } = getXPaddingIdentifier(userID);

    return {
        xPaddingObfsMode: true,
        xPaddingMethod: 'tokenish',
        // 填充放在「请求头里的 query 串」：伪装成一条普通的 GET/POST 查询参数，
        // 比放进 body 更接近被 CDN 大量转发的真实流量形态。
        xPaddingPlacement: 'queryInHeader',
        xPaddingHeader: header,
        xPaddingKey: key
    };
}
