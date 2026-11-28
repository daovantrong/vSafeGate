import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("15.235.192.20", port=2222, username="trong", password="Trong@152310", timeout=15)
sftp = c.open_sftp()
for local_p, remote_p in [
    (r"d:\vSafeGate\dist-web\api_heartbeat.php", "/tmp/u_heartbeat.php"),
    (r"d:\vSafeGate\dist-web\api_report.php", "/tmp/u_report.php"),
    (r"d:\vSafeGate\dist-web\api_stats.php", "/tmp/u_stats.php"),
    (r"d:\vSafeGate\dist-web\hub.php", "/tmp/u_hub.php"),
    (r"d:\vSafeGate\dist-web\index.php", "/tmp/u_index.php"),
]:
    sftp.put(local_p, remote_p)

schema_sql = """CREATE TABLE IF NOT EXISTS nodes (
  server_id VARCHAR(40) PRIMARY KEY,
  node_label VARCHAR(128) NOT NULL DEFAULT '',
  version VARCHAR(32) NOT NULL DEFAULT '',
  os_name VARCHAR(32) NOT NULL DEFAULT '',
  arch VARCHAR(16) NOT NULL DEFAULT '',
  active_bans INT UNSIGNED NOT NULL DEFAULT 0,
  threats_blocked BIGINT UNSIGNED NOT NULL DEFAULT 0,
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS server_id VARCHAR(40) NOT NULL DEFAULT '' AFTER source_node;
ALTER TABLE blocked_ips ADD INDEX IF NOT EXISTS idx_server_id (server_id);
"""
with sftp.file("/tmp/nodes_schema.sql", "w") as f:
    f.write(schema_sql)
sftp.close()

cmd = """echo Trong@152310 | sudo -S bash -c '
set -e
W="/www/wwwroot/vsafegate.trong.pro"
mv -f /tmp/u_heartbeat.php "$W/api/heartbeat.php"
mv -f /tmp/u_report.php "$W/api/report.php"
mv -f /tmp/u_stats.php "$W/api/stats.php"
mv -f /tmp/u_hub.php "$W/hub.php"
mv -f /tmp/u_index.php "$W/index.php"
chown www:www "$W/api/heartbeat.php" "$W/api/report.php" "$W/api/stats.php" "$W/hub.php" "$W/index.php"
chmod 644 "$W/api/heartbeat.php" "$W/api/report.php" "$W/api/stats.php" "$W/hub.php" "$W/index.php"

mysql -u vsafegate_trong_pro -pvsafegate_trong_pro vsafegate_trong_pro < /tmp/nodes_schema.sql
rm -f /tmp/nodes_schema.sql

/www/server/php/85/bin/php -l "$W/api/heartbeat.php"
/www/server/php/85/bin/php -l "$W/api/report.php"
/www/server/php/85/bin/php -l "$W/api/stats.php"
/www/server/php/85/bin/php -l "$W/hub.php"
/www/server/php/85/bin/php -l "$W/index.php"
echo "HOME=$(curl -sk -o /dev/null -w %{http_code} https://vsafegate.trong.pro/)"
echo "HUB=$(curl -sk -o /dev/null -w %{http_code} https://vsafegate.trong.pro/hub.php)"
curl -sk "https://vsafegate.trong.pro/api/stats.php"
echo ""
'"""
stdin, stdout, stderr = c.exec_command(cmd, timeout=45)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:", err)
c.close()
