<?php
require_once __DIR__ . "/../db.php";
header("Content-Type: application/json; charset=utf-8");

$verFile = __DIR__ . "/../releases/VERSION";
$version = is_file($verFile) ? trim((string)file_get_contents($verFile)) : "1.0.1";
$pdo = get_db();

if (isset($_GET["ip"]) && trim((string)$_GET["ip"]) !== "") {
    $qIp = trim((string)$_GET["ip"]);
    if (!filter_var($qIp, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        echo json_encode(["error" => "Địa chỉ IP không hợp lệ"]);
        exit;
    }
    $stmt = $pdo->prepare("SELECT ip, reason, layer, source_node, report_count, expires_at, first_seen, last_seen, active, (active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())) AS currently_blocked FROM blocked_ips WHERE ip = ? LIMIT 1");
    $stmt->execute([$qIp]);
    $row = $stmt->fetch();
    echo json_encode([
        "query" => $qIp,
        "found" => (bool)$row,
        "currently_blocked" => $row ? (bool)$row["currently_blocked"] : false,
        "record" => $row ?: null,
    ]);
    exit;
}

// 15-second file cache to protect MySQL from public traffic spikes
$cacheFile = sys_get_temp_dir() . "/vsg_hub_stats_cache.json";
if (is_file($cacheFile) && (time() - (int)filemtime($cacheFile)) < 15) {
    $cached = @file_get_contents($cacheFile);
    if ($cached !== false && $cached !== "") {
        echo $cached;
        exit;
    }
}

$summary = $pdo->query("
    SELECT
      SUM(CASE WHEN active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()) THEN 1 ELSE 0 END) AS active_ips,
      SUM(CASE WHEN active = 0 OR (expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()) THEN 1 ELSE 0 END) AS expired_ips,
      COALESCE(SUM(report_count), 0) AS total_reports,
      COUNT(DISTINCT NULLIF(server_id, '')) AS reporting_servers,
      SUM(CASE WHEN last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) AS last_24h_ips,
      SUM(CASE WHEN active = 1 AND expires_at IS NULL THEN 1 ELSE 0 END) AS permanent_ips,
      MAX(last_seen) AS last_report_at
    FROM blocked_ips
")->fetch();

$nodeStats = $pdo->query("
    SELECT
      COUNT(*) AS installed_servers,
      SUM(CASE WHEN last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 5 MINUTE) THEN 1 ELSE 0 END) AS live_servers,
      COALESCE(SUM(active_bans), 0) AS total_node_active_bans,
      COALESCE(SUM(threats_blocked), 0) AS total_threats_blocked
    FROM nodes
")->fetch();

$byLayer = $pdo->query("
    SELECT COALESCE(NULLIF(layer, ''), 'Kernel ipset') AS name, COUNT(*) AS ip_count, COALESCE(SUM(report_count), 0) AS reports
    FROM blocked_ips
    WHERE active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())
    GROUP BY name
    ORDER BY ip_count DESC
    LIMIT 10
")->fetchAll();

$topNodes = $pdo->query("
    SELECT server_id, node_label, version, os_name, arch, active_bans, threats_blocked, last_seen,
           (last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 5 MINUTE)) AS is_live
    FROM nodes
    ORDER BY last_seen DESC
    LIMIT 20
")->fetchAll();

$topReasons = $pdo->query("
    SELECT COALESCE(NULLIF(reason, ''), 'Unspecified') AS reason, COUNT(*) AS ip_count, COALESCE(SUM(report_count), 0) AS reports
    FROM blocked_ips
    WHERE active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())
    GROUP BY reason
    ORDER BY reports DESC
    LIMIT 8
")->fetchAll();

$timeline = $pdo->query("
    SELECT DATE(first_seen) AS day, COUNT(*) AS new_ips, COALESCE(SUM(report_count), 0) AS reports
    FROM blocked_ips
    WHERE first_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
    GROUP BY DATE(first_seen)
    ORDER BY day ASC
")->fetchAll();

$out = json_encode([
    "version" => $version,
    "live_servers" => (int)($nodeStats["live_servers"] ?? 0),
    "installed_servers" => (int)($nodeStats["installed_servers"] ?? 0),
    "total_node_active_bans" => (int)($nodeStats["total_node_active_bans"] ?? 0),
    "total_threats_blocked" => (int)($nodeStats["total_threats_blocked"] ?? 0),
    "active_ips" => (int)($summary["active_ips"] ?? 0),
    "expired_ips" => (int)($summary["expired_ips"] ?? 0),
    "total_reports" => (int)($summary["total_reports"] ?? 0),
    "last_24h_ips" => (int)($summary["last_24h_ips"] ?? 0),
    "permanent_ips" => (int)($summary["permanent_ips"] ?? 0),
    "last_report_at" => $summary["last_report_at"] ?? null,
    "by_layer" => $byLayer,
    "nodes" => $topNodes,
    "top_reasons" => $topReasons,
    "timeline_7d" => $timeline,
    "install_url" => "https://vsafegate.trong.pro/install.sh",
    "releases_url" => "https://vsafegate.trong.pro/releases/",
]);
@file_put_contents($cacheFile, $out, LOCK_EX);
echo $out;
