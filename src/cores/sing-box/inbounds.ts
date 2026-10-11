import { MixedInbound, TunInbound } from "#types/sing-box";

export const tun: TunInbound = {
    type: "tun",
    tag: "tun-in",
    address: ["172.19.0.1/28"],
    mtu: 9000,
    auto_route: true,
    strict_route: true,
    // 必须显式写 system：
    //   gvisor / mixed 都依赖 gVisor 网络栈，需要客户端二进制带 `with_gvisor` 编译标签，
    //   否则内核启动 TUN 时直接失败 —— “start inbound/tun[tun-in]: gVisor is not included in this build”。
    //   而省略该字段的默认值就是 gvisor，同样会失败；system 用内核原生 TCP/IP，任何构建都可用。
    stack: "system"
}

export function buildMixedInbound(): MixedInbound {
    const { allowLANConnection } = globalThis.settings;
    return {
        type: "mixed",
        tag: "mixed-in",
        listen: allowLANConnection ? "0.0.0.0" : "127.0.0.1",
        listen_port: 2080
    };
}