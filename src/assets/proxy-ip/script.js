// 背景 iframe：URL 池随机（带随机 query 绕过 5 分钟缓存，每次刷新换背景）
(function initFallbackBg() {
    const bg = document.getElementById('fallback-bg');
    if (bg) {
        bg.src = '/img?t=' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    }
})();

loadGeoData();

// 单行提示行（仅静态文案，不承载第三方数据）
function appendNoticeRow(tableBody, text) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = text;
    row.appendChild(cell);
    tableBody.appendChild(row);
}

async function loadGeoData() {
    const tableBody = document.querySelector("#geo-table tbody");
    try {
        const res = await fetch("/proxy-ip/get");
        const { success, body, message } = await res.json();
        
        if (!success) {
            throw new Error(`Fetching Proxy IPs failed at ${res.url} - ${message}`);
        }

        if (!body.length) {
            tableBody.replaceChildren();
            appendNoticeRow(tableBody, "Failed to get Proxy IPs");
            return;
        }

        tableBody.replaceChildren();

        body.forEach((item, index) => {
            const row = document.createElement("tr");
            const flag = item.countryCode 
                ? String.fromCodePoint(...[...item.countryCode].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) 
                : '';

            // 第三方字段一律走 textContent / addEventListener，绝不经 innerHTML 或内联事件属性
            const indexCell = document.createElement("td");
            indexCell.textContent = index + 1;
            row.appendChild(indexCell);

            const ipCell = document.createElement("td");
            const copyIcon = document.createElement("span");
            copyIcon.className = "material-symbols-rounded";
            copyIcon.textContent = "content_copy";
            copyIcon.addEventListener("click", () => copyToClipboard(item.ip));
            ipCell.appendChild(copyIcon);
            ipCell.appendChild(document.createTextNode(' ' + (item.ip || "-")));
            row.appendChild(ipCell);

            const countryCell = document.createElement("td");
            countryCell.textContent = flag + ' ' + (item.country || "-");
            row.appendChild(countryCell);

            const cityCell = document.createElement("td");
            cityCell.textContent = item.city || "-";
            row.appendChild(cityCell);

            const ispCell = document.createElement("td");
            ispCell.textContent = item.isp || "-";
            row.appendChild(ispCell);

            tableBody.appendChild(row);
        });

    } catch (err) {
        tableBody.replaceChildren();
        appendNoticeRow(tableBody, `Error: ${err.message}`);
        console.error(err);
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
        .then(() => alert('✅ Copied to clipboard:\n\n' + text))
        .catch(error => console.error('Failed to copy:', error));
}
