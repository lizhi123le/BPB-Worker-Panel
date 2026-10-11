import { MixedInbound, TunInbound } from "#types/sing-box";

export const tun: TunInbound = {
    type: "tun",
    tag: "tun-in",
    address: ["172.19.0.1/28"],
    mtu: 9000,
    auto_route: true,
    strict_route: true
    // 不下发 `stack`：sing-box 1.15.0 起该选项已弃用、1.17.0 将移除，
    // 官方迁移口径就是「省略它以使用 sing-tun 自带的 TCP/IP 栈」（性能/功耗/内存均优于 gvisor/mixed，
    // 且不再依赖 `with_gvisor` 编译标签）。旧版显式写 system 是为绕开 “gVisor is not included in this build”
    // 的启动失败；省略后该问题同样不存在。
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