<?php
require_once __DIR__ . "/db.php";
$pdo = get_db();
$q = trim((string)($_GET["q"] ?? ""));
$layer = trim((string)($_GET["layer"] ?? ""));
$status = trim((string)($_GET["status"] ?? "active"));
$sort = trim((string)($_GET["sort"] ?? "recent"));
$page = max(1, (int)($_GET["page"] ?? 1));
$perPage = 50;
$offset = ($page - 1) * $perPage;

$summary = $pdo->query("
    SELECT
      SUM(CASE WHEN active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()) THEN 1 ELSE 0 END) AS active_ips,
      SUM(CASE WHEN active = 0 OR (expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()) THEN 1 ELSE 0 END) AS expired_ips,
      COALESCE(SUM(report_count), 0) AS total_reports,
      SUM(CASE WHEN last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) AS last_24h,
      SUM(CASE WHEN active = 1 AND expires_at IS NULL THEN 1 ELSE 0 END) AS permanent_ips
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
$nodesList = $pdo->query("SELECT server_id, node_label, version, os_name, arch, active_bans, threats_blocked, last_seen, (last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 5 MINUTE)) AS is_live FROM nodes ORDER BY last_seen DESC LIMIT 12")->fetchAll();

$byLayer = $pdo->query("SELECT COALESCE(NULLIF(layer, ''), 'Kernel ipset') AS name, COUNT(*) AS cnt FROM blocked_ips WHERE active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()) GROUP BY name ORDER BY cnt DESC LIMIT 6")->fetchAll();
$topNodes = $pdo->query("SELECT COALESCE(NULLIF(source_node, ''), 'unknown') AS node, COUNT(*) AS ips, COALESCE(SUM(report_count),0) AS reports FROM blocked_ips GROUP BY node ORDER BY reports DESC LIMIT 6")->fetchAll();
$topReasons = $pdo->query("SELECT COALESCE(NULLIF(reason, ''), 'Unspecified') AS reason, COUNT(*) AS ips, COALESCE(SUM(report_count),0) AS reports FROM blocked_ips WHERE active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()) GROUP BY reason ORDER BY reports DESC LIMIT 6")->fetchAll();
$timeline = $pdo->query("SELECT DATE(first_seen) AS day, COUNT(*) AS cnt FROM blocked_ips WHERE first_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY) GROUP BY DATE(first_seen) ORDER BY day ASC")->fetchAll();

$where = ["1=1"];
$params = [];
if ($status === "active") {
    $where[] = "active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())";
} elseif ($status === "expired") {
    $where[] = "(active = 0 OR (expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()))";
}
if ($q !== "") {
    $where[] = "(ip LIKE ? OR reason LIKE ? OR source_node LIKE ?)";
    $like = "%" . $q . "%";
    $params[] = $like; $params[] = $like; $params[] = $like;
}
if ($layer !== "") {
    $where[] = "layer = ?";
    $params[] = $layer;
}
$orderBy = $sort === "reports" ? "report_count DESC, last_seen DESC" : "last_seen DESC";

$cntStmt = $pdo->prepare("SELECT COUNT(*) FROM blocked_ips WHERE " . implode(" AND ", $where));
$cntStmt->execute($params);
$totalRows = (int)$cntStmt->fetchColumn();
$totalPages = max(1, (int)ceil($totalRows / $perPage));

$sql = "SELECT ip, reason, layer, source_node, report_count, expires_at, first_seen, last_seen, active FROM blocked_ips WHERE " . implode(" AND ", $where) . " ORDER BY $orderBy LIMIT $perPage OFFSET $offset";
$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

$lookupResult = null;
if ($q !== "" && filter_var($q, FILTER_VALIDATE_IP)) {
    $lStmt = $pdo->prepare("SELECT ip, reason, layer, source_node, report_count, expires_at, first_seen, last_seen, (active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())) AS blocked FROM blocked_ips WHERE ip = ? LIMIT 1");
    $lStmt->execute([$q]);
    $lookupResult = $lStmt->fetch() ?: ["ip" => $q, "blocked" => false, "clean" => true];
}

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8"); }
$maxBar = 1;
foreach ($timeline as $t) { if ((int)$t["cnt"] > $maxBar) $maxBar = (int)$t["cnt"]; }
?>
<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Threat Intelligence Hub — vSafeGate</title>
  <style>
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#0b0f19;color:#e5e7eb}
    a{color:#34d399;text-decoration:none}a:hover{text-decoration:underline}
    .wrap{max-width:1200px;margin:0 auto;padding:24px 18px 60px}
    .nav{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid #1f2937;padding-bottom:16px;margin-bottom:22px}
    .links{display:flex;gap:16px;font-size:13px;font-weight:600}
    .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:20px}
    .card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:15px}
    .lbl{font-size:11px;color:#9ca3af;text-transform:uppercase}.val{font-size:24px;font-weight:800;color:#10b981;margin-top:4px;font-family:monospace}
    .panels{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-bottom:20px}
    .panel-title{font-size:13px;font-weight:700;color:#fff;margin:0 0 12px}
    .bar-row{display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:8px}
    .bar-bg{flex:1;height:8px;background:#1f2937;border-radius:999px;overflow:hidden}
    .bar-fill{height:100%;background:#10b981;border-radius:999px}
    .timeline{display:flex;align-items:flex-end;gap:8px;height:90px;padding-top:10px}
    .t-col{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;height:100%}
    .t-bar-wrap{flex:1;width:100%;display:flex;align-items:flex-end;justify-content:center}
    .t-bar{width:70%;background:linear-gradient(180deg,#10b981,#047857);border-radius:4px 4px 0 0;min-height:4px}
    .t-lbl{font-size:10px;color:#9ca3af;font-family:monospace}
    .filter{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;align-items:center}
    .filter input,.filter select{background:#111827;border:1px solid #374151;color:#fff;padding:8px 12px;border-radius:8px;font-size:13px}
    .btn{background:#059669;color:#fff;border:none;padding:8px 14px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer}
    .btn-sec{background:#1f2937;color:#e5e7eb;border:1px solid #374151;padding:8px 12px;border-radius:8px;font-size:12px;font-weight:600;display:inline-block}
    .lookup-box{padding:14px 16px;border-radius:12px;margin-bottom:16px;font-size:13px}
    .lookup-bad{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.4);color:#fca5a5}
    .lookup-ok{background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.4);color:#6ee7b7}
    table{width:100%;border-collapse:collapse;background:#111827;border:1px solid #1f2937;border-radius:12px;overflow:hidden;font-size:13px}
    th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #1f2937}
    th{background:#0f172a;color:#9ca3af;font-size:11px;text-transform:uppercase}
    .mono{font-family:monospace;color:#f87171}
    .badge{background:#1f2937;color:#93c5fd;padding:2px 8px;border-radius:999px;font-size:11px}
    .pag{display:flex;justify-content:space-between;align-items:center;margin-top:14px;font-size:12px;color:#9ca3af}
  </style>
</head>
<body>
<div class="wrap">
  <div class="nav">
    <div>
      <h1 style="margin:0;font-size:20px;color:#fff">vSafeGate Threat Intelligence Hub</h1>
      <div style="font-size:12px;color:#9ca3af;margin-top:4px">Tra cứu &amp; thống kê IP tấn công công khai (không cần đăng nhập)</div>
    </div>
    <div class="links">
      <a href="/">Trang Chủ</a>
      <a href="/hub.php" style="color:#fff">Threat Hub</a>
      <a href="/releases/">Kho Binary</a>
      <a href="/api/stats.php">API Stats</a>
    </div>
  </div>

  <div class="kpis">
    <div class="card"><div class="lbl">Server Đang Live</div><div class="val"><?= (int)($nodeStats["live_servers"] ?? 0) ?> <span style="font-size:13px;color:#9ca3af">/ <?= (int)($nodeStats["installed_servers"] ?? 0) ?> đã cài</span></div></div>
    <div class="card"><div class="lbl">Threats Đã Chặn</div><div class="val" style="color:#f87171"><?= number_format((int)($nodeStats["total_threats"] ?? 0)) ?></div></div>
    <div class="card"><div class="lbl">IP Đang Chặn (Hub)</div><div class="val"><?= (int)($summary["active_ips"] ?? 0) ?></div></div>
    <div class="card"><div class="lbl">IP Chặn (Các Node)</div><div class="val" style="color:#fbbf24"><?= (int)($nodeStats["total_node_bans"] ?? 0) ?></div></div>
    <div class="card"><div class="lbl">Mới Trong 24h</div><div class="val" style="color:#38bdf8"><?= (int)($summary["last_24h"] ?? 0) ?></div></div>
    <div class="card"><div class="lbl">Tổng Lượt Báo Cáo</div><div class="val" style="color:#a78bfa"><?= (int)($summary["total_reports"] ?? 0) ?></div></div>
  </div>

  <div class="panels">
    <div class="card">
      <h3 class="panel-title">Xu Hướng 7 Ngày Gần Nhất</h3>
      <?php if (!$timeline): ?>
        <div style="font-size:12px;color:#6b7280">Chưa có dữ liệu 7 ngày.</div>
      <?php else: ?>
        <div class="timeline">
          <?php foreach ($timeline as $t): $pct = max(6, round(((int)$t["cnt"] / $maxBar) * 100)); ?>
            <div class="t-col" title="<?= h($t["day"]) ?>: <?= (int)$t["cnt"] ?> IP">
              <div class="t-lbl"><?= (int)$t["cnt"] ?></div>
              <div class="t-bar-wrap"><div class="t-bar" style="height:<?= $pct ?>%"></div></div>
              <div class="t-lbl"><?= h(substr($t["day"], 5)) ?></div>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </div>

    <div class="card">
      <h3 class="panel-title">Phân Bố Theo Lớp Phòng Thủ</h3>
      <?php if (!$byLayer): ?><div style="font-size:12px;color:#6b7280">Chưa có dữ liệu.</div>
      <?php else: $maxL = max(1, (int)$byLayer[0]["cnt"]); foreach ($byLayer as $l): ?>
        <div class="bar-row">
          <span style="width:105px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= h($l["name"]) ?></span>
          <div class="bar-bg"><div class="bar-fill" style="width:<?= round(((int)$l["cnt"]/$maxL)*100) ?>%"></div></div>
          <span style="font-family:monospace;width:36px;text-align:right"><?= (int)$l["cnt"] ?></span>
        </div>
      <?php endforeach; endif; ?>
    </div>

    <div class="card">
      <h3 class="panel-title">Máy Chủ vSafeGate (Theo Hardware ID)</h3>
      <?php if (!$nodesList): ?><div style="font-size:12px;color:#6b7280">Chưa có node nào gửi heartbeat.</div>
      <?php else: foreach ($nodesList as $nd): ?>
        <div class="bar-row" style="justify-content:space-between">
          <span style="color:#e5e7eb;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
            <span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:<?= $nd["is_live"] ? "#10b981" : "#6b7280" ?>;margin-right:5px"></span>
            <?= h($nd["node_label"] ?: substr($nd["server_id"], 0, 14)) ?>
          </span>
          <span class="badge"><?= (int)$nd["active_bans"] ?> ban · <?= (int)$nd["threats_blocked"] ?> threat</span>
        </div>
      <?php endforeach; endif; ?>
    </div>

    <div class="card">
      <h3 class="panel-title">Top Lý Do Tấn Công</h3>
      <?php if (!$topReasons): ?><div style="font-size:12px;color:#6b7280">Chưa có dữ liệu.</div>
      <?php else: foreach ($topReasons as $rs): ?>
        <div class="bar-row" style="justify-content:space-between;gap:8px">
          <span style="color:#d1d5db;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= h($rs["reason"]) ?></span>
          <span style="font-family:monospace;color:#fbbf24"><?= (int)$rs["reports"] ?></span>
        </div>
      <?php endforeach; endif; ?>
    </div>
  </div>

  <?php if ($lookupResult !== null): ?>
    <?php if (!empty($lookupResult["blocked"])): ?>
      <div class="lookup-box lookup-bad">
        <strong>CẢNH BÁO IP ĐANG BỊ CHẶN:</strong> <code style="color:#fff"><?= h($lookupResult["ip"]) ?></code> — Lý do: <strong><?= h($lookupResult["reason"] ?: "N/A") ?></strong> · Lớp: <?= h($lookupResult["layer"]) ?> · Node: <?= h($lookupResult["source_node"]) ?> · Số lần: <?= (int)$lookupResult["report_count"] ?>
      </div>
    <?php else: ?>
      <div class="lookup-box lookup-ok">
        <strong>IP AN TOÀN:</strong> <code><?= h($lookupResult["ip"]) ?></code> hiện không nằm trong danh sách chặn hoạt động.
      </div>
    <?php endif; ?>
  <?php endif; ?>

  <form class="filter" method="get" action="/hub.php">
    <input type="text" name="q" value="<?= h($q) ?>" placeholder="Tra cứu IP chính xác hoặc tìm từ khóa (IP, lý do, node)..." style="flex:1;min-width:240px" />
    <select name="layer">
      <option value="">Tất cả lớp chặn</option>
      <option value="Kernel ipset" <?= $layer==="Kernel ipset"?"selected":"" ?>>Kernel ipset</option>
      <option value="L7 Shield" <?= $layer==="L7 Shield"?"selected":"" ?>>L7 Shield</option>
      <option value="WAF" <?= $layer==="WAF"?"selected":"" ?>>WAF</option>
    </select>
    <select name="status">
      <option value="active" <?= $status==="active"?"selected":"" ?>>Đang chặn</option>
      <option value="expired" <?= $status==="expired"?"selected":"" ?>>Đã hết hạn / gỡ</option>
      <option value="all" <?= $status==="all"?"selected":"" ?>>Tất cả</option>
    </select>
    <select name="sort">
      <option value="recent" <?= $sort==="recent"?"selected":"" ?>>Mới nhất</option>
      <option value="reports" <?= $sort==="reports"?"selected":"" ?>>Nhiều báo cáo nhất</option>
    </select>
    <button class="btn" type="submit">Tra Cứu / Lọc</button>
    <a class="btn-sec" href="/api/export.php?format=txt" target="_blank">Xuất TXT</a>
    <a class="btn-sec" href="/api/export.php?format=json" target="_blank">Xuất JSON</a>
  </form>

  <table>
    <thead><tr><th>IP / CIDR</th><th>Lý Do</th><th>Lớp Chặn</th><th>Node Nguồn</th><th>Số Lần</th><th>Hết Hạn (UTC)</th><th>Cập Nhật (UTC)</th></tr></thead>
    <tbody>
    <?php if (!$rows): ?>
      <tr><td colspan="7" style="text-align:center;color:#6b7280;padding:24px">Chưa có IP nào phù hợp điều kiện lọc.</td></tr>
    <?php else: foreach ($rows as $r): ?>
      <tr>
        <td class="mono"><?= h($r["ip"]) ?></td>
        <td><?= h($r["reason"]) ?></td>
        <td><span class="badge"><?= h($r["layer"] ?: "Kernel ipset") ?></span></td>
        <td><?= h($r["source_node"]) ?></td>
        <td style="font-family:monospace;font-weight:700;color:#fbbf24"><?= (int)$r["report_count"] ?></td>
        <td><?= h($r["expires_at"] ?: "Vĩnh viễn") ?></td>
        <td><?= h($r["last_seen"]) ?></td>
      </tr>
    <?php endforeach; endif; ?>
    </tbody>
  </table>

  <div class="pag">
    <span>Hiển thị <?= count($rows) ?> / <?= $totalRows ?> bản ghi (Trang <?= $page ?>/<?= $totalPages ?>)</span>
    <div style="display:flex;gap:8px">
      <?php if ($page > 1): ?><a class="btn-sec" href="?<?= http_build_query(["q"=>$q,"layer"=>$layer,"status"=>$status,"sort"=>$sort,"page"=>$page-1]) ?>">← Trước</a><?php endif; ?>
      <?php if ($page < $totalPages): ?><a class="btn-sec" href="?<?= http_build_query(["q"=>$q,"layer"=>$layer,"status"=>$status,"sort"=>$sort,"page"=>$page+1]) ?>">Sau →</a><?php endif; ?>
    </div>
  </div>
</div>
</body>
</html>
