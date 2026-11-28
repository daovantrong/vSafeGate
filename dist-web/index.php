<?php
require_once __DIR__ . "/db.php";
$verFile = __DIR__ . "/releases/VERSION";
$version = is_file($verFile) ? trim((string)file_get_contents($verFile)) : "1.0.1";
$pdo = get_db();
$stats = $pdo->query("
    SELECT
      SUM(CASE WHEN active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()) THEN 1 ELSE 0 END) AS total,
      COALESCE(SUM(report_count),0) AS reports,
      SUM(CASE WHEN last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) AS last_24h
    FROM blocked_ips
")->fetch();
$nodeStats = $pdo->query("
    SELECT
      COUNT(*) AS installed_servers,
      SUM(CASE WHEN last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 5 MINUTE) THEN 1 ELSE 0 END) AS live_servers,
      COALESCE(SUM(active_bans), 0) AS total_node_bans,
      COALESCE(SUM(threats_blocked), 0) AS total_threats
    FROM nodes
")->fetch();
$recent = $pdo->query("SELECT ip, reason, layer, source_node, report_count, last_seen FROM blocked_ips WHERE active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()) ORDER BY last_seen DESC LIMIT 5")->fetchAll();
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8"); }
?>
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>vSafeGate v<?= h($version) ?> — Tường Lửa Linux &amp; WAF Chuyên Nghiệp</title>
  <style>
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#0b0f19;color:#e5e7eb;line-height:1.6}
    a{color:#34d399;text-decoration:none}
    .wrap{max-width:1120px;margin:0 auto;padding:24px 18px 60px}
    .nav{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid #1f2937;padding-bottom:16px}
    .brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:18px;color:#fff}
    .ver{font-size:11px;font-family:monospace;background:#064e3b;color:#6ee7b7;padding:2px 8px;border-radius:999px;border:1px solid #059669}
    .links{display:flex;gap:18px;font-size:13px;font-weight:600}
    .hero{padding:42px 0 28px;text-align:center}
    .hero h1{font-size:clamp(28px,4vw,42px);margin:0 0 12px;color:#fff;letter-spacing:-0.02em}
    .hero p{max-width:740px;margin:0 auto 22px;color:#9ca3af;font-size:15px}
    .tabs{display:flex;justify-content:center;gap:8px;flex-wrap:wrap;margin-bottom:10px}
    .tab{background:#111827;border:1px solid #374151;color:#9ca3af;padding:6px 12px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer}
    .tab.active{background:#064e3b;border-color:#10b981;color:#6ee7b7}
    .cmd-box{max-width:760px;margin:0 auto;background:#030712;border:1px solid #1f2937;border-radius:14px;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px;text-align:left}
    .cmd-box code{font-family:ui-monospace,SFMono-Regular,monospace;font-size:13px;color:#34d399;overflow-x:auto;white-space:nowrap}
    .btn{background:#059669;color:#fff;border:none;padding:9px 16px;border-radius:9px;font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap}
    .btn:hover{background:#10b981}
    .btn-sec{background:#1f2937;color:#e5e7eb;border:1px solid #374151;padding:9px 16px;border-radius:9px;font-size:12px;font-weight:600;display:inline-block}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:26px 0}
    .stat{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px;text-align:center}
    .stat .n{font-size:26px;font-weight:800;color:#10b981;font-family:monospace}
    .stat .l{font-size:12px;color:#9ca3af;margin-top:4px}
    .lookup{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:18px;margin-bottom:24px}
    .lookup form{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
    .lookup input{flex:1;min-width:220px;background:#030712;border:1px solid #374151;color:#fff;padding:9px 12px;border-radius:8px;font-family:monospace;font-size:13px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:16px;margin-top:20px}
    .card{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:18px}
    .card h3{margin:0 0 8px;font-size:15px;color:#fff}
    .card p{margin:0;font-size:13px;color:#9ca3af}
    table{width:100%;border-collapse:collapse;background:#111827;border:1px solid #1f2937;border-radius:12px;overflow:hidden;font-size:13px;margin-top:12px}
    th,td{padding:9px 12px;text-align:left;border-bottom:1px solid #1f2937}
    th{background:#0f172a;color:#9ca3af;font-size:11px;text-transform:uppercase}
  </style>
</head>
<body>
<div class="wrap">
  <div class="nav">
    <div class="brand">
      <span>vSafeGate</span>
      <span class="ver">v<?= h($version) ?> · Web Edition</span>
    </div>
    <div class="links">
      <a href="/" style="color:#fff">Trang Chủ</a>
      <a href="/hub.php">Threat Hub (<?= (int)($stats["total"] ?? 0) ?> IP)</a>
      <a href="/releases/">Kho Binary</a>
      <a href="/api/stats.php">API Stats</a>
      <a href="/install.sh">install.sh</a>
    </div>
  </div>

  <div class="hero">
    <h1>Tường Lửa Linux &amp; WAF Chuyên Nghiệp 2 Tầng</h1>
    <p>Lọc gói tin tầng nhân (<code>iptables</code>/<code>ipset</code>), ẩn định danh Pre-TLS, chống HTTP Flood (<code>vsafegate_shield</code>), Coraza OWASP CRS v4, L4 Zero-Copy <code>splice(2)</code> và đồng bộ danh sách IP chặn chung toàn hệ thống.</p>
    <div class="tabs">
      <button class="tab active" onclick="setCmd('install', this)">1. Cài Đặt Mới</button>
      <button class="tab" onclick="setCmd('update', this)">2. Cập Nhật</button>
      <button class="tab" onclick="setCmd('cli', this)">3. CLI Quản Trị</button>
      <button class="tab" onclick="setCmd('uninstall', this)">4. Gỡ Cài Đặt</button>
    </div>
    <div class="cmd-box">
      <code id="install-cmd">curl -fsSL https://vsafegate.trong.pro/install.sh | sudo bash</code>
      <button class="btn" onclick="copyInstall()">Copy Lệnh</button>
    </div>
    <div style="margin-top:14px;display:flex;justify-content:center;gap:10px;flex-wrap:wrap">
      <a class="btn-sec" href="/hub.php">Mở Threat Intelligence Hub →</a>
      <a class="btn-sec" href="/releases/">Kho Binary &amp; SHA256</a>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="n"><?= (int)($nodeStats["live_servers"] ?? 0) ?> / <?= (int)($nodeStats["installed_servers"] ?? 0) ?></div><div class="l">Server Đang Live / Đã Cài</div></div>
    <div class="stat"><div class="n" style="color:#f87171"><?= number_format((int)($nodeStats["total_threats"] ?? 0)) ?></div><div class="l">Threats Đã Chặn (Toàn Mạng)</div></div>
    <div class="stat"><div class="n"><?= (int)($stats["total"] ?? 0) ?></div><div class="l">IP Chặn Chung (Hub)</div></div>
    <div class="stat"><div class="n" style="color:#38bdf8"><?= (int)($stats["last_24h"] ?? 0) ?></div><div class="l">IP Mới 24h Qua</div></div>
    <div class="stat"><div class="n">v<?= h($version) ?></div><div class="l">Phiên Bản Web Deploy</div></div>
  </div>

  <div class="lookup">
    <div style="font-size:14px;font-weight:700;color:#fff;margin-bottom:8px">Tra Cứu Nhanh Uy Tín IP (Công Khai)</div>
    <form onsubmit="checkIP(event)">
      <input type="text" id="quick-ip" placeholder="Nhập địa chỉ IP cần kiểm tra (vd: 203.0.113.50)..." />
      <button class="btn" type="submit">Kiểm Tra IP</button>
      <a class="btn-sec" href="/hub.php">Tra Cứu Nâng Cao →</a>
    </form>
    <div id="quick-ip-res" style="margin-top:10px;font-size:13px"></div>
  </div>

  <div class="grid">
    <div class="card"><h3>🛡️ Kernel L3/L4 Dual-Stack</h3><p>Chain riêng <code>VSAFEGATE_INPUT</code> / <code>VSAFEGATE6_INPUT</code>, chỉ cho phép IPv6 Link-Local, SYN/UDP/ICMP hashlimit và đồng bộ <code>vsafegate-shared</code>.</p></div>
    <div class="card"><h3>🕵️ Pre-TLS Stealth &amp; L7 Shield</h3><p>Đọc SNI &amp; JA4-light trước handshake, ngắt im lặng scan IP trực tiếp, tích hợp Rate Limit và JS PoW Challenge HMAC-SHA256.</p></div>
    <div class="card"><h3>☁️ Cloudflare Auto-Proxy &amp; SSL 3 Tab</h3><p>Tự bật mây cam khi DDoS flood, cấp SSL DNS-01/HTTP-01 tự động (fallback Tự ký nếu lỗi) và hỗ trợ Custom PEM.</p></div>
    <div class="card"><h3>⚡ L4 Zero-Copy Proxy</h3><p>Chuyển tiếp TCP bằng <code>splice(2)</code> &amp; UDP kèm Load Balancing, PROXY Protocol v1/v2 và giới hạn kết nối theo IP.</p></div>
    <div class="card"><h3>🔔 Cảnh Báo Đa Kênh &amp; SOC</h3><p>Thu thập metrics thực tế từ Caddy &amp; Kernel, gửi cảnh báo qua Email SMTP, Telegram, Discord và Webhook HMAC-SHA256.</p></div>
    <div class="card"><h3>🌐 Triển Khai Độc Lập Trên Web</h3><p>Toàn bộ <code>install.sh</code> và binary tĩnh <code>amd64</code>/<code>arm64</code> được host trực tiếp tại <code>vsafegate.trong.pro</code> với kiểm tra SHA256.</p></div>
  </div>

  <div style="margin-top:28px">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <h3 style="margin:0;font-size:15px;color:#fff">IP Tấn Công Mới Nhất Trên Hub</h3>
      <a href="/hub.php" style="font-size:12px">Xem tất cả →</a>
    </div>
    <table>
      <thead><tr><th>IP</th><th>Lý Do</th><th>Lớp Chặn</th><th>Node</th><th>Số Lần</th><th>Thời Gian (UTC)</th></tr></thead>
      <tbody>
      <?php if (!$recent): ?>
        <tr><td colspan="6" style="text-align:center;color:#6b7280;padding:18px">Chưa có IP tấn công nào được ghi nhận.</td></tr>
      <?php else: foreach ($recent as $r): ?>
        <tr>
          <td style="font-family:monospace;color:#f87171"><?= h($r["ip"]) ?></td>
          <td><?= h($r["reason"]) ?></td>
          <td><?= h($r["layer"]) ?></td>
          <td><?= h($r["source_node"]) ?></td>
          <td style="font-family:monospace;color:#fbbf24"><?= (int)$r["report_count"] ?></td>
          <td><?= h($r["last_seen"]) ?></td>
        </tr>
      <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
</div>
<script>
const cmds = {
  install: "curl -fsSL https://vsafegate.trong.pro/install.sh | sudo bash",
  update: "sudo vsafegate update",
  cli: "sudo vsafegate status   # hỗ trợ: status | restart | logs | update | uninstall",
  uninstall: "sudo vsafegate uninstall"
};
function setCmd(k, btn){
  document.getElementById("install-cmd").innerText = cmds[k] || cmds.install;
  document.querySelectorAll(".tab").forEach(b=>b.classList.remove("active"));
  if(btn) btn.classList.add("active");
}
function copyInstall(){
  const t = document.getElementById("install-cmd").innerText;
  navigator.clipboard.writeText(t).then(()=>alert("Đã copy lệnh!"));
}
async function checkIP(e){
  e.preventDefault();
  const ip = document.getElementById("quick-ip").value.trim();
  const box = document.getElementById("quick-ip-res");
  if(!ip){ box.innerHTML=""; return; }
  box.innerHTML = "Đang tra cứu...";
  try{
    const r = await fetch("/api/stats.php?ip=" + encodeURIComponent(ip));
    const d = await r.json();
    if(d.currently_blocked && d.record){
      box.innerHTML = `<span style="color:#fca5a5"><strong>ĐANG BỊ CHẶN:</strong> ${d.record.ip} — ${d.record.reason || "N/A"} (Node: ${d.record.source_node}, ${d.record.report_count} lượt)</span>`;
    } else {
      box.innerHTML = `<span style="color:#6ee7b7"><strong>SẠCH:</strong> ${ip} không nằm trong danh sách chặn hoạt động.</span>`;
    }
  }catch(err){
    box.innerHTML = `<span style="color:#fca5a5">Lỗi tra cứu: ${err}</span>`;
  }
}
</script>
</body>
</html>
