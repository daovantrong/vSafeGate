import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("15.235.192.20", port=2222, username="trong", password="Trong@152310", timeout=15)
sftp = c.open_sftp()
for local_p, remote_p in [
    (r"d:\vSafeGate\dist-web\api_stats.php", "/tmp/u_stats.php"),
    (r"d:\vSafeGate\dist-web\api_export.php", "/tmp/u_export.php"),
    (r"d:\vSafeGate\dist-web\hub.php", "/tmp/u_hub.php"),
    (r"d:\vSafeGate\dist-web\index.php", "/tmp/u_index.php"),
]:
    sftp.put(local_p, remote_p)
sftp.close()

cmd = """echo Trong@152310 | sudo -S bash -c '
set -e
W="/www/wwwroot/vsafegate.trong.pro"
mv -f /tmp/u_stats.php "$W/api/stats.php"
mv -f /tmp/u_export.php "$W/api/export.php"
mv -f /tmp/u_hub.php "$W/hub.php"
mv -f /tmp/u_index.php "$W/index.php"
chown www:www "$W/api/stats.php" "$W/api/export.php" "$W/hub.php" "$W/index.php"
chmod 644 "$W/api/stats.php" "$W/api/export.php" "$W/hub.php" "$W/index.php"

/www/server/php/85/bin/php -l "$W/api/stats.php"
/www/server/php/85/bin/php -l "$W/api/export.php"
/www/server/php/85/bin/php -l "$W/hub.php"
/www/server/php/85/bin/php -l "$W/index.php"

echo "HOME=$(curl -sk -o /dev/null -w %{http_code} https://vsafegate.trong.pro/)"
echo "HUB=$(curl -sk -o /dev/null -w %{http_code} https://vsafegate.trong.pro/hub.php)"
echo "RELEASES=$(curl -sk -o /dev/null -w %{http_code} https://vsafegate.trong.pro/releases/)"
echo "EXPORT_TXT=$(curl -sk -o /dev/null -w %{http_code} https://vsafegate.trong.pro/api/export.php?format=txt)"
echo "STATS_JSON=$(curl -sk https://vsafegate.trong.pro/api/stats.php)"
echo "LOOKUP_IP=$(curl -sk "https://vsafegate.trong.pro/api/stats.php?ip=8.8.8.8")"
'"""
stdin, stdout, stderr = c.exec_command(cmd, timeout=45)
print(stdout.read().decode())
c.close()
