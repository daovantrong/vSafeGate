<?php
require_once __DIR__ . "/../db.php";
header("Content-Type: application/json; charset=utf-8");
require_api_key();

if (($_SERVER["REQUEST_METHOD"] ?? "GET") !== "POST") {
    http_response_code(405);
    echo json_encode(["error" => "Method Not Allowed"]);
    exit;
}

$raw = file_get_contents("php://input", false, null, 0, 16384);
$data = json_decode($raw ?: "{}", true);
if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid JSON"]);
    exit;
}

$serverId = strtolower(trim((string)($data["server_id"] ?? "")));
if (!preg_match('/^vsg_[a-f0-9]{24}$/', $serverId)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid server_id format"]);
    exit;
}

// Per-server_id & per-IP rate limit (max 1 heartbeat per 30s)
$rlDir = sys_get_temp_dir() . "/vsg_hb_rl";
if (!is_dir($rlDir)) @mkdir($rlDir, 0750, true);
$rlFile = $rlDir . "/" . sha1($serverId) . ".lock";
if (is_file($rlFile) && (time() - (int)filemtime($rlFile)) < 30) {
    http_response_code(429);
    echo json_encode(["error" => "Rate limited: heartbeat too frequent"]);
    exit;
}
@touch($rlFile);

$nodeLabel = mb_substr(trim((string)($data["node"] ?? "")), 0, 120);
$version   = mb_substr(trim((string)($data["version"] ?? "")), 0, 30);
$osName    = mb_substr(trim((string)($data["os"] ?? "")), 0, 30);
$arch      = mb_substr(trim((string)($data["arch"] ?? "")), 0, 16);
$activeBans = max(0, min(10000000, (int)($data["active_bans"] ?? 0)));
$threatsBlocked = max(0, min(1000000000, (int)($data["threats_blocked"] ?? 0)));

$pdo = get_db();
$sql = "INSERT INTO nodes (server_id, node_label, version, os_name, arch, active_bans, threats_blocked, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
          node_label = IF(VALUES(node_label) <> '', VALUES(node_label), node_label),
          version = IF(VALUES(version) <> '', VALUES(version), version),
          os_name = IF(VALUES(os_name) <> '', VALUES(os_name), os_name),
          arch = IF(VALUES(arch) <> '', VALUES(arch), arch),
          active_bans = VALUES(active_bans),
          threats_blocked = GREATEST(threats_blocked, VALUES(threats_blocked)),
          last_seen = UTC_TIMESTAMP()";
$stmt = $pdo->prepare($sql);
$stmt->execute([$serverId, $nodeLabel, $version, $osName, $arch, $activeBans, $threatsBlocked]);

echo json_encode(["status" => "ok", "server_id" => $serverId]);
