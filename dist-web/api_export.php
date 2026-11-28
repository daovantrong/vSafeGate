<?php
require_once __DIR__ . "/../db.php";
$pdo = get_db();
$format = strtolower((string)($_GET["format"] ?? "txt"));
$stmt = $pdo->query("SELECT ip, reason, layer, source_node, report_count, expires_at, last_seen FROM blocked_ips WHERE active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP()) ORDER BY last_seen DESC LIMIT 50000");
$rows = $stmt->fetchAll();

if ($format === "json") {
    header("Content-Type: application/json; charset=utf-8");
    header("Content-Disposition: inline; filename=vsafegate-shared-blocklist.json");
    echo json_encode(["generated_at" => gmdate("c"), "count" => count($rows), "items" => $rows]);
    exit;
}

header("Content-Type: text/plain; charset=utf-8");
header("Content-Disposition: inline; filename=vsafegate-shared-blocklist.txt");
echo "# vSafeGate Shared Threat Intelligence Blocklist (" . gmdate("c") . ")\n";
foreach ($rows as $r) {
    echo $r["ip"] . "\n";
}
