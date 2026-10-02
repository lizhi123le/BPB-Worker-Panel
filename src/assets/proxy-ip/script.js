// 背景 iframe：URL 池随机（带随机 query 绕过 5 分钟缓存，每次刷新换背景）
(function initFallbackBg() {
    const bg = document.getElementById('fallback-bg');
    if (bg) {
        bg.src = '/img?t=' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    }
})();

loadGeoData();

async function loadGeoData() {
    const tableBody = document.querySelector("#geo-table tbody");
    try {
        const res = await fetch("/proxy-ip/get");
        const { success, body, message } = await res.json();
        
        if (!success) {
            throw new Error(`Fetching Proxy IPs failed at ${res.url} - ${message}`);
        }

        if (!body.length) {
            tableBody.innerHTML = "<tr><td colspan='5'>Failed to get Proxy IPs</td></tr>";
            return;
        }

        tableBody.innerHTML = "";

        body.forEach((item, index) => {
            const row = document.createElement("tr");
            const flag = item.countryCode 
                ? String.fromCodePoint(...[...item.countryCode].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) 
                : '';

            row.innerHTML =
                `
                    <td>${index + 1}</td>
                    <td>
                        <span class="material-symbols-rounded" onclick="copyToClipboard('${item.ip}')">
                            content_copy
                        </span>
                        ${item.ip || "-"}
                    </td>
                    <td>${flag} ${item.country || "-"}</td>
                    <td>${item.city || "-"}</td>
                    <td>${item.isp || "-"}</td>
                `;
            tableBody.appendChild(row);
        });

    } catch (err) {
        tableBody.innerHTML = `<tr><td colspan='5'>Error: ${err.message}</td></tr>`;
        console.error(err);
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
        .then(() => alert('✅ Copied to clipboard:\n\n' + text))
        .catch(error => console.error('Failed to copy:', error));
}
