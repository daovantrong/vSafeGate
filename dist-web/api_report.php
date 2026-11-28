<?php
require_once __DIR__ . "/../db.php";
header("Content-Type: application/json; charset=utf-8");
require_api_key();

$method = $_SERVER["REQUEST_METHOD"] ?? "GET";
$raw = file_get_contents("php://input", false, null, 0, 16384);
$data = json_decode($raw ?: "{}", true);
if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid JSON"]);
    exit;
}

$ip = is_valid_public_ip_or_cidr((string)($data["ip"] ?? ""));
if ($ip === null) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid or private/reserved IP/CIDR"]);
    exit;
}

$serverId = strtolower(trim((string)($data["server_id"] ?? "")));
if ($serverId !== "" && !preg_match('/^vsg_[a-f0-9]{24}$/', $serverId)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid server_id format"]);
    exit;
}

// Per-source IP rate limit (max 120 reports per 60s window) to prevent spam/flood
$srcIp = $_SERVER["REMOTE_ADDR"] ?? "unknown";
$rlDir = sys_get_temp_dir() . "/vsg_rep_rl";
if (!is_dir($rlDir)) @mkdir($rlDir, 0750, true);
$rlFile = $rlDir . "/" . sha1($srcIp . "|" . $serverId) . ".cnt";
$nowWin = (int)floor(time() / 60);
$cnt = 0;
if (is_file($rlFile)) {
    $parts = explode(":", (string)@file_get_contents($rlFile));
    if (count($parts) === 2 && (int)$parts[0] === $nowWin) {
        $cnt = (int)$parts[1];
    }
}
if ($cnt >= 120) {
    http_response_code(429);
    echo json_encode(["error" => "Rate limited: too many IP reports"]);
    exit;
}
@file_put_contents($rlFile, $nowWin . ":" . ($cnt + 1), LOCK_EX);

$pdo = get_db();

if ($method === "DELETE") {
    $stmt = $pdo->prepare("UPDATE blocked_ips SET active = 0 WHERE ip = ?");
    $stmt->execute([$ip]);
    echo json_encode(["status" => "ok", "ip" => $ip, "active" => false]);
    exit;
}

if ($method !== "POST") {
    http_response_code(405);
    echo json_encode(["error" => "Method Not Allowed"]);
    exit;
}

$reason = mb_substr(trim((string)($data["reason"] ?? "")), 0, 250);
$layer = mb_substr(trim((string)($data["layer"] ?? "")), 0, 60);
$node = mb_substr(trim((string)($data["node"] ?? ($serverId ?: $srcIp))), 0, 120);
$ttlHours = isset($data["ttl_hours"]) ? (int)$data["ttl_hours"] : 24;
$expiresAt = null;
if ($ttlHours > 0) {
    $expiresAt = gmdate("Y-m-d H:i:s", time() + min($ttlHours, 8760) * 3600);
}

$sql = "INSERT INTO blocked_ips (ip, reason, layer, source_node, server_id, report_count, expires_at, first_seen, last_seen, active)
        VALUES (?, ?, ?, ?, ?, 1, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP(), 1)
        ON DUPLICATE KEY UPDATE
          reason = IF(VALUES(reason) <> '', VALUES(reason), reason),
          layer = IF(VALUES(layer) <> '', VALUES(layer), layer),
          source_node = IF(VALUES(source_node) <> '', VALUES(source_node), source_node),
          server_id = IF(VALUES(server_id) <> '', VALUES(server_id), server_id),
          report_count = report_count + 1,
          expires_at = IF(VALUES(expires_at) IS NULL OR (expires_at IS NOT NULL AND VALUES(expires_at) > expires_at), VALUES(expires_at), expires_at),
          last_seen = UTC_TIMESTAMP(),
          active = 1";
$stmt = $pdo->prepare($sql);
$stmt->execute([$ip, $reason, $layer, $node, $serverId, $expiresAt]);

echo json_encode(["status" => "ok", "ip" => $ip, "server_id" => $serverId, "expires_at" => $expiresAt]);
