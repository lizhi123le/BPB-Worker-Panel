# :material-new-box:{ .md .middle } Workers manual installation

It is highly recommended to use [Wizard installation](./wizard.md) to avoid Cloudflare 1101 error, user errors and also save time to setup panel.

## Installation

### 1. Create Cloudflare Account

If you don’t have a Cloudflare account, create one [from here](https://dash.cloudflare.com/sign-up). You only need an email for registration. Due to Cloudflare’s restrictions, use a reputable email provider like Gmail.

### 2. Create worker

First, download the Worker code from [from here](https://github.com/bia-pain-bache/BPB-Worker-Panel/releases/latest/download/worker.js).

In your Cloudflare account, navigate to the `Developer Platform` tab and click `Create application`, from `Workers` tab find `Start with Hello World!` and `Get started`.

Enter a desired name, which will form your panel’s domain and `Deploy`.

!!! danger
    Choose a name that does not include the word `bpb`, as this may trigger Cloudflare’s detection and result in a `1101` error.

Then click `Edit code` here. In the left sidebar, delete the `worker.js` file and upload the new one. If it gives an error, delete the `package-lock.json` file too. Since the code has become large, copying and pasting on mobile is difficult — refer to the image below and upload it properly. On mobile, open the side menu, long-press the Explorer, and click `Upload...`.

![Mobile upload](../images/worker-mobile-upload.jpg)

Finally, `Deploy` the Worker.

!!! tip
    Note that the panel update process is exactly the same — you delete the old files, upload the new ones, and deploy. Previous settings remain safe, only the panel gets updated.

First, at the top of the dashboard, click `Visit`. You’ll see an error saying you need to set the UUID and Trojan Password first. It includes a link (Secrets generator) — open it in your browser and keep it open for the next step.

![Generate secrets](../images/generate-secrets.jpg)

### 3. Create KV

Return to the Worker dashboard and follow these steps:

![Workers dashboard](../images/nav-worker-dash.jpg)

From here, go to the `KV` page:

![KV dashboard](../images/nav-dash-kv.jpg)

In the KV section, click `Create`, give it a name (e.g., Test), and click `Add`.

Again, go to the `Developer Platform` section, open the Worker you just created, go to `Bindings`. Click `Add binding` and choose `KV Namespace`. From the dropdown, select the KV you just created (e.g., Test). What’s important is the first field — it **must** be set to `kv`. Then click `Deploy`.

![Bind KV](../images/workers-bind-kv.jpg)

### 4. Set UUID, Trojan password and Subscription path

Click `Copy all` from the `Secrets generator` page provided earlier, In Cloudflare dashboard go to `Settings` section, locate the `Variables and Secrets` section. Click `Add` and paste into the `Variable name` field and click `Deploy`. This will automatically add these 3 parameters to panel.

Again click `Visit` in your worker dashboard, you see speedtest in browser, just add `/panel` to the end of address and see your panel:

It will ask you to set a new password and log in — that’s it.  
Installation is complete; the rest of the information below may not be needed by everyone.  
For settings tutorials and tips, refer to the [main guide](../configuration/index.md).

## Advanced configuration (Optional)

### Fixing the Proxy IP

By default, the code uses multiple Proxy IPs randomly, assigning a new random IP for each connection to Cloudflare addresses (covering much of the web). This IP rotation may cause issues, particularly for traders. From version 2.3.5 onward, you can change the Proxy IP via the panel and update the subscription. However, the method below is recommended:

!!! note
    Changing the Proxy IP via the panel requires updating the subscription if the IP stops working, which can disrupt donated configurations, as users without an active subscription cannot update them. Use this method only for personal use. Other methods don’t require subscription updates.

To change the Proxy IP, go to `Workers & Pages`, open your Worker, then go to `Settings` → `Variables and Secrets`:

![Workers env variable](../images/workers-variables.jpg)

Click `Add`, write `PROXY_IP` (uppercase) as the `Variable name`.
You can check available Proxy IPs by clicking the icon beside `Proxy IPs / Domains` field in the panel or visiting `/proxy-ip` in browser, which lists IPs by region and ISP.

![Proxy IPs](../images/proxy-ips.jpg)

!!! info
    To use multiple Proxy IPs, enter them comma-separated.
    ```title="Example"
    151.213.181.145, 5.163.51.41, bpb.yousef.isegaro.com
    ```

Enter the IPs in the `Value` field and click `Deploy`.

### Fixing the NAT64 Prefixes

By default, the code uses multiple NAT64 prefixes randomly, assigning a new random prefix for each connection to Cloudflare addresses (covering much of the web). This IP rotation may cause issues, particularly for traders. From version 3.4.2 onward, you can change the prefixes via the panel and update the subscription. However, the method below is recommended:

!!! note
    Changing the NAT64 prefixes via the panel requires updating the subscription if the IP stops working, which can disrupt donated configurations, as users without an active subscription cannot update them. Use this method only for personal use. Other methods don’t require subscription updates.

In the project’s `Settings` section, open `Variables and Secrets`, click `Add` and enter `NAT64_PREFIX` (in capital letters) in the first box. Obtain IPs from the following link, which lists IPs from various regions and ISPs:

```text
https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/main/NAT64Prefixes.md
```

!!! info
    To use multiple IPs, fill them comma-separated.
    ```title="Example"
    [2602:fc59:b0:64::], [2602:fc59:11:64::]
    ```

Enter the IPs in the `Value` field and click `Deploy`.

### Setting Fallback Domain

By default, accessing the main Worker domain redirects to the Cloudflare speed test site. To change this, follow the same steps as for the Proxy IP, but set the variable name to `FALLBACK` and provide a domain (without `https://` or `http://`) as the value, e.g., `www.speedtest.net` or `npmjs.org`.  

### Changing the Subscription Path

The default subscription link path uses the same UUID as VLESS. For increased privacy, you can change this. Follow the same steps as above, but set the variable name to `SUB_PATH`. The Secrets generator at `/secrets` provides a `Random Subscription URI path` value, which you can use or replace with a custom value (using allowed characters).

### Adding Custom Domain

Go to your Cloudflare dashboard, open your Worker from `Compute (Workers)` > `Workers & Pages`. Go to `Settings` and at the top, you’ll see `Domains & Routes`. Click `Add +`, then choose `Custom domain`.

Enter a domain (you must own and have activated it on the same account).
  
Suppose your domain is `bpb.com`. You can enter the main domain or a subdomain, like `xyz.bpb.com`, then click `Add domain`.

Cloudflare will connect the Worker to your domain (this might take a while — they say up to 24 hours).

Then click `Add +` again, but this time select `Route`. Choose your domain from the `Zone` section, and in the `Route` section, enter it like this:

```title="Route"
*bpb.com/*
```

You can then access your panel via `https://xyz.bpb.com/panel` and retrieve new subscriptions.

!!! tip
    - If you connect a domain to the Worker, your traffic becomes probably unlimited.
    - Worker panels support non-TLS ports like 80, 8080, etc. But once you add a custom domain, those ports stop working and won’t be available in the panel.

### Tuning the camouflage fallback (optional)

These variables control the reverse-proxy used to disguise the panel domain. **All of them are optional** — leave them unset and the built-in defaults apply. Invalid values fall back to the default and log a warning, so a typo can never take the site down.

| Variable | Default | What it does |
| --- | --- | --- |
| `MASK_REQ_BPS` | `20` | Sustained requests/second allowed through the camouflage proxy (token bucket refill rate). |
| `MASK_REQ_CAP` | `200` | Burst capacity for the same bucket. One cold first-paint is roughly 30 requests. |
| `MASK_TEXT_BPS` | `1048576` | Sustained **rewritten text** bytes/second. This is the real CPU driver (decode + replace + encode). |
| `MASK_TEXT_CAP` | `16777216` | Burst capacity for rewritten text. Keep it comfortably larger than your largest page. |
| `MASK_TEXT_IP_CAP` | `4194304` | Per-IP rewritten-text budget per 60 s window. Prevents one IP from exhausting the whole isolate. Minimum accepted value: `65536`. |
| `MASK_CACHE_NOISE_EXTRA` | *(empty)* | Comma-separated extra query parameters to ignore when building the cache key. ⚠️ **Only add parameters that never change the content** — adding `id`, `page` or `token` will make different pages share one cache entry. |
| `MASK_CACHE_TS_NORM` | `1` | Set to `0` to disable timestamp normalisation in cache keys (rollback switch). |
| `MASK_IMG_MODE` | `shell` | Set to `data` to fall back to the legacy single-response inline `data:` URI image page (rollback switch). |
| `WS_UPLINK_ISOLATE_MB` | `32` | Isolate-wide budget (MB) for buffered uplink data, split across active WebSocket connections. |
| `WS_MAX_CONNECTIONS` | `128` | WebSocket connections allowed **per isolate** (clamped to 1–1024; `0`/invalid falls back to the default). Each connection costs ≈136 KiB of steady-state buffers (worst case ≈336 KiB), so 128 ≈ 17–43 MiB and 256 ≈ 34–86 MiB of the 128 MB isolate. 128 leaves room for the ~12 MiB disguise cache; raising it is allowed without any warning, just watch isolate memory yourself. |
| `WS_DOWNLINK_BPS` | `10000000` | Downlink rate cap in **bytes per second** (10 MB/s ≈ 80 Mbps). It is the only downlink flow control that exists (the Workers `WebSocket` has no `bufferedAmount` and `send()` returns `void`), and it caps **all** downlink traffic. Setting it far above the client's real throughput means the cap never binds and the in-isolate send queue grows unbounded, which surfaces as `internal error; reference = …` (1101). Raise it for >80 Mbps links, or set `0` to disable. The burst allowance is now a **separate** knob (`WS_DOWNLINK_BURST_KB`). |
| `WS_DOWNLINK_BURST_KB` | `2048` | Per-connection **burst allowance** (token-bucket capacity) in KiB — the maximum a connection may dump into the runtime queue before throttling starts. It is capped by `WS_DOWNLINK_BPS` and floored at 256 KiB (4 read blocks, which must exceed one block or the bucket deadlocks). Why it is separate: the bucket used to be sized by the rate, so 10 MB/s meant 10 MB *per connection* of instant burst — a client running a speed test with 8 parallel connections could queue 80 MB in a 128 MB isolate and get the whole isolate reclaimed (`internal error`, not 1102). Set `0` to restore the legacy behaviour (capacity = rate). |
| `WS_SESSION_MAX_MB` | `900` | Per-connection downlink byte budget. On reaching it the connection is closed cleanly and the client reconnects (~5 min of 4K at ≈3.1 MB/s, ~19 min of 1080p; 90 s only if the client really sustains the 10 MB/s cap), which avoids the platform killing the whole isolate. Set `0` to disable. |
| `WS_IDLE_TIMEOUT_S` | `600` | Close a WebSocket session after this many seconds with **no traffic in either direction** (10 min). This is the only guard for *slow or idle* sessions — `WS_SESSION_MAX_MB` counts sent bytes, so an idle connection never trips it and can sit until the platform load-sheds it. Set `0` to disable. |
| `WS_MAX_SESSION_S` | `900` | Hard limit on a single WebSocket session's lifetime (15 min). Kept below the platform's ~20 min runtime-update grace window because Cloudflare ends long-lived connections with `$workers.outcome = "loadShed"`, which clients see as `1101 internal error; reference = …`. Closing first turns that into a clean reconnect. Set `0` to disable. |
| `WS_DOWNLINK_STATS` | `0` | Set to `1` to emit the per-second `downlink …` throughput line without switching the whole panel to Log Level = debug. |
| `XP_MAX_CONNECTIONS` | `32` | Concurrent XHTTP (POST / stream-one) tunnels allowed per isolate, clamped to 1–1024. Each costs roughly the same buffers as a WebSocket connection. |
| `XP_IDLE_TIMEOUT_S` | `30` | Close an XHTTP tunnel after this many seconds with **no traffic in either direction**. Set `0` to disable — needed if your player pauses or buffers for long stretches (a 4K stream paused for >30 s is otherwise torn down and has to re-establish the POST). |
| `XP_MAX_QUEUED_MB` | `8` | Downlink queue limit for an XHTTP tunnel. Set `0` to disable. |
| `XP_QUEUE_GRACE_S` | `15` | How long the downlink queue may stay **above** `XP_MAX_QUEUED_MB` before the tunnel is closed. Downlink is rate-limited (`WS_DOWNLINK_BPS`) first; this grace absorbs spikes (seeks, segment switches, GC pauses). `0` restores the old immediate-close behaviour. |

!!! note "Progressive stutter during long 4K playback"
    If playback starts fine, degrades over minutes and finally drops, the cause is **the lack of send-side backpressure**, not copy overhead: anything the client cannot absorb is queued inside the isolate, which shows up first as growing latency and then as a memory/CPU kill. `WS_DOWNLINK_BPS` (default 10 MB/s) is the counter-measure; set it slightly above your real client throughput. To calibrate, set panel **Log Level = debug** and watch `downlink …KiB/s … cap=…B/s capWait=…ms/1000ms budget=…B`: `capWait≈0` means the cap never bound in that second (the client is slower than the cap — lower it), `capWait` close to `1000ms` means the cap is the bottleneck (raise it). Each log line reports only the last one-second window.

!!! warning "Rollback order"
    If the camouflage site misbehaves after an upgrade, revert in this order: (1) `MASK_IMG_MODE=data`, (2) `MASK_CACHE_TS_NORM=0`, (3) raise the `MASK_*` limits, (4) redeploy the previous `worker.js`.

## Updating the Panel

To update your panel, download the new worker.js file [from here](https://github.com/bia-pain-bache/BPB-Worker-Panel/releases/latest/download/worker.js). In your Cloudflare account, go to `Compute (Workers)` > `Workers & Pages`, select your Worker project, edit it, delete old worker, upload new one and Deploy.
