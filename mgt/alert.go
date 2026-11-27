package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityCritical AlertSeverity = "critical"
)

type AlertEvent struct {
	Key       string            `json:"key"`
	Category  string            `json:"category"` // ddos_spike, autoproxy, ip_ban, caddy_health, cert_expiry, upstream_unhealthy
	Severity  AlertSeverity     `json:"severity"`
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	Host      string            `json:"host,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// AlertChannel defines an extensible delivery target (Email SMTP, Telegram, Webhook, etc.).
type AlertChannel interface {
	Name() string
	Send(ctx context.Context, subject string, events []AlertEvent) error
}

func sanitizeEmailHeaderVal(s string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(strings.TrimSpace(s))
}

func validateSMTPConfig(cfg *SMTPConfig) error {
	if cfg == nil {
		return errors.New("smtp config is required")
	}
	cfg.SMTPHost = sanitizeEmailHeaderVal(cfg.SMTPHost)
	cfg.TLSMode = strings.ToLower(strings.TrimSpace(cfg.TLSMode))
	cfg.Username = sanitizeEmailHeaderVal(cfg.Username)
	cfg.FromAddress = sanitizeEmailHeaderVal(cfg.FromAddress)

	if cfg.TLSMode == "" {
		switch cfg.SMTPPort {
		case 465:
			cfg.TLSMode = "tls"
		case 25:
			cfg.TLSMode = "none"
		default:
			cfg.TLSMode = "starttls"
		}
	}
	switch cfg.TLSMode {
	case "starttls", "tls", "none":
	default:
		return fmt.Errorf("tls_mode không hợp lệ: %q (chỉ hỗ trợ starttls, tls, none)", cfg.TLSMode)
	}
	if cfg.SMTPPort <= 0 {
		switch cfg.TLSMode {
		case "tls":
			cfg.SMTPPort = 465
		case "none":
			cfg.SMTPPort = 25
		default:
			cfg.SMTPPort = 587
		}
	}
	if cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 {
		return errors.New("smtp_port phải trong khoảng 1..65535")
	}
	if cfg.CooldownMinutes < 0 || cfg.CooldownMinutes > 1440 {
		return errors.New("cooldown_minutes phải trong khoảng 0..1440")
	}
	if cfg.DropSpikeThresholdPS < 0 {
		return errors.New("drop_spike_threshold_ps không được âm")
	}
	if cfg.CertExpiryWarnDays < 0 || cfg.CertExpiryWarnDays > 365 {
		return errors.New("cert_expiry_warn_days phải trong khoảng 0..365")
	}

	// Clean recipient list
	cleanTo := make([]string, 0, len(cfg.ToAddresses))
	seen := make(map[string]struct{})
	for _, raw := range cfg.ToAddresses {
		addrStr := sanitizeEmailHeaderVal(raw)
		if addrStr == "" {
			continue
		}
		parsed, err := mail.ParseAddress(addrStr)
		if err != nil {
			return fmt.Errorf("địa chỉ email nhận không hợp lệ: %q", addrStr)
		}
		if _, dup := seen[parsed.Address]; !dup {
			seen[parsed.Address] = struct{}{}
			cleanTo = append(cleanTo, parsed.Address)
		}
	}
	cfg.ToAddresses = cleanTo

	if cfg.Enabled {
		if cfg.SMTPHost == "" {
			return errors.New("smtp_host không được để trống khi bật cảnh báo Email")
		}
		if cfg.FromAddress == "" {
			return errors.New("from_address không được để trống")
		}
		if _, err := mail.ParseAddress(cfg.FromAddress); err != nil {
			return fmt.Errorf("from_address không hợp lệ: %q", cfg.FromAddress)
		}
		if len(cfg.ToAddresses) == 0 {
			return errors.New("cần ít nhất 1 địa chỉ email người nhận (to_addresses)")
		}
	} else if cfg.FromAddress != "" {
		if _, err := mail.ParseAddress(cfg.FromAddress); err != nil {
			return fmt.Errorf("from_address không hợp lệ: %q", cfg.FromAddress)
		}
	}
	return nil
}

// unencryptedAllowedPlainAuth supports AUTH PLAIN on explicitly configured TLSMode=="none" internal relays.
type unencryptedAllowedPlainAuth struct {
	username string
	password string
}

func (a unencryptedAllowedPlainAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	resp := []byte("\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a unencryptedAllowedPlainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

type SMTPAlertChannel struct {
	cfg SMTPConfig
}

func NewSMTPAlertChannel(cfg SMTPConfig) *SMTPAlertChannel {
	return &SMTPAlertChannel{cfg: cfg}
}

func (c *SMTPAlertChannel) Name() string {
	return "smtp"
}

func formatAlertEmailBody(subject string, events []AlertEvent) string {
	var b strings.Builder
	b.WriteString("vSafeGate Security Gateway Alert Notification\r\n")
	b.WriteString("============================================\r\n")
	b.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	b.WriteString(fmt.Sprintf("Generated: %s\r\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Events Included: %d\r\n\r\n", len(events)))

	for i, ev := range events {
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		b.WriteString(fmt.Sprintf("--- Event #%d [%s] (%s) ---\r\n", i+1, strings.ToUpper(string(ev.Severity)), ev.Category))
		b.WriteString(fmt.Sprintf("Time:    %s\r\n", ts.UTC().Format(time.RFC3339)))
		b.WriteString(fmt.Sprintf("Title:   %s\r\n", ev.Title))
		if ev.Host != "" {
			b.WriteString(fmt.Sprintf("Host:    %s\r\n", ev.Host))
		}
		if ev.Message != "" {
			b.WriteString(fmt.Sprintf("Message: %s\r\n", ev.Message))
		}
		if len(ev.Details) > 0 {
			for k, v := range ev.Details {
				b.WriteString(fmt.Sprintf("  %s: %s\r\n", k, v))
			}
		}
		b.WriteString("\r\n")
	}
	return b.String()
}

func buildRFC5322Email(fromAddr string, toAddrs []string, subject, body string) []byte {
	cleanFrom := sanitizeEmailHeaderVal(fromAddr)
	cleanSubj := sanitizeEmailHeaderVal(subject)
	encodedSubj := mime.QEncoding.Encode("utf-8", cleanSubj)
	msgIDRand := make([]byte, 8)
	_, _ = rand.Read(msgIDRand)
	msgID := fmt.Sprintf("<%d.%s@vsafegate.local>", time.Now().UnixNano(), hex.EncodeToString(msgIDRand))

	cleanTos := make([]string, 0, len(toAddrs))
	for _, t := range toAddrs {
		if s := sanitizeEmailHeaderVal(t); s != "" {
			cleanTos = append(cleanTos, s)
		}
	}

	var buf bytes.Buffer
	buf.WriteString("From: " + cleanFrom + "\r\n")
	buf.WriteString("To: " + strings.Join(cleanTos, ", ") + "\r\n")
	buf.WriteString("Subject: " + encodedSubj + "\r\n")
	buf.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	buf.WriteString("Message-ID: " + msgID + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(body)
	return buf.Bytes()
}

func (c *SMTPAlertChannel) Send(ctx context.Context, subject string, events []AlertEvent) error {
	cfg := c.cfg
	cfg.Enabled = true
	if err := validateSMTPConfig(&cfg); err != nil {
		return err
	}

	fromParsed, err := mail.ParseAddress(cfg.FromAddress)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	tlsCfg := &tls.Config{
		ServerName:         cfg.SMTPHost,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	var conn net.Conn
	if cfg.TLSMode == "tls" {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsCfg}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("kết nối SMTP %s thất bại: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP handshake thất bại: %w", err)
	}
	defer func() { _ = client.Close() }()

	if cfg.TLSMode == "starttls" {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return errors.New("máy chủ SMTP không hỗ trợ STARTTLS")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS thất bại: %w", err)
		}
	}

	if cfg.Username != "" || cfg.Password != "" {
		if ok, _ := client.Extension("AUTH"); ok {
			var auth smtp.Auth
			if cfg.TLSMode == "none" {
				auth = unencryptedAllowedPlainAuth{username: cfg.Username, password: cfg.Password}
			} else {
				auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
			}
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("xác thực SMTP thất bại: %w", err)
			}
		}
	}

	if err := client.Mail(fromParsed.Address); err != nil {
		return fmt.Errorf("SMTP MAIL FROM thất bại: %w", err)
	}
	for _, rcpt := range cfg.ToAddresses {
		p, err := mail.ParseAddress(rcpt)
		if err != nil {
			return err
		}
		if err := client.Rcpt(p.Address); err != nil {
			return fmt.Errorf("SMTP RCPT TO (%s) thất bại: %w", p.Address, err)
		}
	}

	body := formatAlertEmailBody(subject, events)
	msgBytes := buildRFC5322Email(cfg.FromAddress, cfg.ToAddresses, subject, body)

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA thất bại: %w", err)
	}
	if _, err := wc.Write(msgBytes); err != nil {
		_ = wc.Close()
		return fmt.Errorf("ghi nội dung email thất bại: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("hoàn tất DATA email thất bại: %w", err)
	}
	_ = client.Quit()
	return nil
}

type alertBucket struct {
	lastSent     time.Time
	pending      []AlertEvent
	droppedCount int
}

type AlertRecord struct {
	Timestamp time.Time     `json:"timestamp"`
	Category  string        `json:"category"`
	Severity  AlertSeverity `json:"severity"`
	Title     string        `json:"title"`
	Count     int           `json:"count"`
	Delivered bool          `json:"delivered"`
	Error     string        `json:"error,omitempty"`
}

type AlertEngine struct {
	mu            sync.Mutex
	state         *AppState
	extraChannels []AlertChannel
	buckets       map[string]*alertBucket
	prevUnhealthy map[string]bool
	certAlertAt   map[string]time.Time
	history       []AlertRecord
	sentCount     int64
	bufferedCount int64
	cooldownOverride time.Duration
	nowFn            func() time.Time

	stopCh   chan struct{}
	doneCh   chan struct{}
	started  bool
	stopOnce sync.Once
}

func NewAlertEngine(s *AppState) *AlertEngine {
	return &AlertEngine{
		state:         s,
		buckets:       make(map[string]*alertBucket),
		prevUnhealthy: make(map[string]bool),
		certAlertAt:   make(map[string]time.Time),
		nowFn:         time.Now,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

func (e *AlertEngine) AddChannel(ch AlertChannel) {
	if ch == nil {
		return
	}
	e.mu.Lock()
	e.extraChannels = append(e.extraChannels, ch)
	e.mu.Unlock()
}

func (e *AlertEngine) now() time.Time {
	if e != nil && e.nowFn != nil {
		return e.nowFn()
	}
	return time.Now()
}

func (e *AlertEngine) effectiveCooldown(cfg SMTPConfig) time.Duration {
	if e.cooldownOverride > 0 {
		return e.cooldownOverride
	}
	mins := cfg.CooldownMinutes
	if mins <= 0 {
		mins = 10
	}
	return time.Duration(mins) * time.Minute
}

func (e *AlertEngine) Start() {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()

	go func() {
		defer close(e.doneCh)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-e.stopCh:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				e.FlushDue(ctx)
				cancel()
			}
		}
	}()
}

func (e *AlertEngine) Stop() {
	if e == nil {
		return
	}
	e.mu.Lock()
	started := e.started
	e.mu.Unlock()
	if !started {
		return
	}
	e.stopOnce.Do(func() {
		close(e.stopCh)
	})
	<-e.doneCh
}

func (e *AlertEngine) activeChannelsLocked() ([]AlertChannel, SMTPConfig) {
	var smtpCfg SMTPConfig
	var alertCfg AlertChannelsConfig
	if e.state != nil {
		e.state.mu.RLock()
		smtpCfg = e.state.config.SMTP
		alertCfg = e.state.config.Alerts
		e.state.mu.RUnlock()
	}
	channels := make([]AlertChannel, 0, 4+len(e.extraChannels))
	if smtpCfg.Enabled && smtpCfg.SMTPHost != "" && len(smtpCfg.ToAddresses) > 0 {
		channels = append(channels, NewSMTPAlertChannel(smtpCfg))
	}
	if alertCfg.TelegramEnabled && strings.TrimSpace(alertCfg.TelegramBotToken) != "" && strings.TrimSpace(alertCfg.TelegramChatID) != "" {
		channels = append(channels, NewTelegramAlertChannel(alertCfg.TelegramBotToken, alertCfg.TelegramChatID))
	}
	if alertCfg.DiscordEnabled && strings.TrimSpace(alertCfg.DiscordWebhookURL) != "" {
		channels = append(channels, NewDiscordAlertChannel(alertCfg.DiscordWebhookURL))
	}
	if alertCfg.WebhookEnabled && strings.TrimSpace(alertCfg.WebhookURL) != "" {
		channels = append(channels, NewWebhookAlertChannel(alertCfg.WebhookURL, alertCfg.WebhookSecret))
	}
	channels = append(channels, e.extraChannels...)
	return channels, smtpCfg
}

func (e *AlertEngine) Notify(ev AlertEvent) {
	if e == nil {
		return
	}
	now := e.now().UTC()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = now
	}
	if ev.Category == "" {
		ev.Category = "general"
	}
	if ev.Severity == "" {
		ev.Severity = AlertSeverityWarning
	}

	e.mu.Lock()
	channels, smtpCfg := e.activeChannelsLocked()
	if len(channels) == 0 {
		e.mu.Unlock()
		return
	}
	cooldown := e.effectiveCooldown(smtpCfg)
	bucketKey := ev.Category
	if (ev.Category == "autoproxy" || ev.Category == "caddy_health") && strings.TrimSpace(ev.Key) != "" {
		bucketKey = ev.Key
	}
	b := e.buckets[bucketKey]
	if b == nil {
		b = &alertBucket{}
		e.buckets[bucketKey] = b
	}

	if b.lastSent.IsZero() || now.Sub(b.lastSent) >= cooldown {
		b.lastSent = now
		e.mu.Unlock()

		subj := fmt.Sprintf("[vSafeGate %s] %s", strings.ToUpper(string(ev.Severity)), ev.Title)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := e.dispatch(ctx, channels, subj, []AlertEvent{ev})
		cancel()
		e.recordHistory(ev.Category, ev.Severity, ev.Title, 1, err)
		return
	}

	if len(b.pending) < 500 {
		b.pending = append(b.pending, ev)
	} else {
		b.droppedCount++
	}
	e.bufferedCount++
	e.mu.Unlock()
}

func (e *AlertEngine) FlushDue(ctx context.Context) {
	if e == nil {
		return
	}
	now := e.now().UTC()

	type flushBatch struct {
		category string
		events   []AlertEvent
		dropped  int
		channels []AlertChannel
	}
	var batches []flushBatch

	e.mu.Lock()
	channels, smtpCfg := e.activeChannelsLocked()
	cooldown := e.effectiveCooldown(smtpCfg)
	if len(channels) > 0 {
		for cat, b := range e.buckets {
			if len(b.pending) == 0 {
				continue
			}
			if now.Sub(b.lastSent) >= cooldown {
				evs := make([]AlertEvent, len(b.pending))
				copy(evs, b.pending)
				dropped := b.droppedCount
				b.pending = nil
				b.droppedCount = 0
				b.lastSent = now
				catName := cat
				if len(evs) > 0 && evs[0].Category != "" {
					catName = evs[0].Category
				}
				batches = append(batches, flushBatch{
					category: catName,
					events:   evs,
					dropped:  dropped,
					channels: channels,
				})
			}
		}
	}
	e.mu.Unlock()

	for _, batch := range batches {
		highest := AlertSeverityInfo
		for _, ev := range batch.events {
			if ev.Severity == AlertSeverityCritical {
				highest = AlertSeverityCritical
				break
			}
			if ev.Severity == AlertSeverityWarning {
				highest = AlertSeverityWarning
			}
		}
		total := len(batch.events) + batch.dropped
		subj := fmt.Sprintf("[vSafeGate %s] Aggregated Alert (%s): %d event(s)", strings.ToUpper(string(highest)), batch.category, total)
		if batch.dropped > 0 {
			batch.events = append(batch.events, AlertEvent{
				Category:  batch.category,
				Severity:  highest,
				Title:     fmt.Sprintf("+%d additional events truncated during burst", batch.dropped),
				Timestamp: now,
			})
		}
		err := e.dispatch(ctx, batch.channels, subj, batch.events)
		e.recordHistory(batch.category, highest, subj, total, err)
	}
}

func (e *AlertEngine) dispatch(ctx context.Context, channels []AlertChannel, subject string, events []AlertEvent) error {
	var firstErr error
	for _, ch := range channels {
		if err := ch.Send(ctx, subject, events); err != nil {
			log.Printf("[AlertEngine] Channel %s send failed: %v", ch.Name(), err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (e *AlertEngine) recordHistory(category string, severity AlertSeverity, title string, count int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		e.sentCount++
	}
	rec := AlertRecord{
		Timestamp: e.now().UTC(),
		Category:  category,
		Severity:  severity,
		Title:     title,
		Count:     count,
		Delivered: err == nil,
	}
	if err != nil {
		rec.Error = err.Error()
	}
	e.history = append([]AlertRecord{rec}, e.history...)
	if len(e.history) > 50 {
		e.history = e.history[:50]
	}
}

func (e *AlertEngine) SendTestEmail(ctx context.Context, override *SMTPConfig) error {
	var cfg SMTPConfig
	if override != nil {
		cfg = *override
	} else if e != nil && e.state != nil {
		e.state.mu.RLock()
		cfg = e.state.config.SMTP
		e.state.mu.RUnlock()
	}
	if (cfg.Password == "" || cfg.Password == "********") && e != nil && e.state != nil {
		e.state.mu.RLock()
		cfg.Password = e.state.config.SMTP.Password
		e.state.mu.RUnlock()
	}
	cfg.Enabled = true
	if err := validateSMTPConfig(&cfg); err != nil {
		return err
	}
	ch := NewSMTPAlertChannel(cfg)
	ev := AlertEvent{
		Key:       "smtp_test",
		Category:  "test",
		Severity:  AlertSeverityInfo,
		Title:     "vSafeGate SMTP Test Email",
		Message:   "Đây là email kiểm tra cấu hình cảnh báo SMTP từ vSafeGate Security Gateway.",
		Timestamp: e.now().UTC(),
		Details: map[string]string{
			"SMTP Host": cfg.SMTPHost,
			"SMTP Port": strconv.Itoa(cfg.SMTPPort),
			"TLS Mode":  cfg.TLSMode,
		},
	}
	return ch.Send(ctx, "[vSafeGate] Email Alert Configuration Test", []AlertEvent{ev})
}

func (e *AlertEngine) StatusSnapshot() map[string]any {
	if e == nil {
		return map[string]any{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	hist := make([]AlertRecord, len(e.history))
	copy(hist, e.history)
	return map[string]any{
		"alerts_sent":     e.sentCount,
		"alerts_buffered": e.bufferedCount,
		"recent_alerts":   hist,
	}
}

func (e *AlertEngine) NotifyIPBan(ip, reason, layer string, ttlHours int) {
	ttlStr := "Permanent"
	if ttlHours > 0 {
		ttlStr = fmt.Sprintf("%dh", ttlHours)
	}
	e.Notify(AlertEvent{
		Key:      "ip_ban:" + ip,
		Category: "ip_ban",
		Severity: AlertSeverityWarning,
		Title:    fmt.Sprintf("IP Banned (%s): %s", layer, ip),
		Message:  reason,
		Details: map[string]string{
			"IP":     ip,
			"Layer":  layer,
			"TTL":    ttlStr,
			"Reason": reason,
		},
	})
}

func (e *AlertEngine) NotifyAutoProxy(domain, action, zoneID string, recordsUpdated int, underAttack bool) {
	sev := AlertSeverityCritical
	title := fmt.Sprintf("Cloudflare Auto-Proxy ACTIVATED for %s", domain)
	msg := fmt.Sprintf("DDoS/Flood threshold exceeded; switched %d DNS record(s) to Proxied (Orange Cloud).", recordsUpdated)
	if action != "activate" {
		sev = AlertSeverityInfo
		title = fmt.Sprintf("Cloudflare Auto-Proxy REVERTED for %s", domain)
		msg = fmt.Sprintf("Traffic normalized after hold time; reverted %d DNS record(s) to DNS-Only.", recordsUpdated)
	}
	e.Notify(AlertEvent{
		Key:      "autoproxy:" + domain + ":" + action,
		Category: "autoproxy",
		Severity: sev,
		Host:     domain,
		Title:    title,
		Message:  msg,
		Details: map[string]string{
			"Action":          action,
			"Zone ID":         zoneID,
			"Records Updated": strconv.Itoa(recordsUpdated),
			"Under Attack":    strconv.FormatBool(underAttack),
		},
	})
}

func (e *AlertEngine) NotifyCaddyEvent(title, message string, severity AlertSeverity) {
	e.Notify(AlertEvent{
		Key:      "caddy_health:" + title,
		Category: "caddy_health",
		Severity: severity,
		Title:    title,
		Message:  message,
	})
}

func (e *AlertEngine) CheckTelemetrySignals(dropPS float64, unhealthy []UpstreamHealthStatus, certs []CertExpiryStatus) {
	if e == nil {
		return
	}
	var thresh float64 = 50.0
	if e.state != nil {
		e.state.mu.RLock()
		if e.state.config.SMTP.DropSpikeThresholdPS > 0 {
			thresh = e.state.config.SMTP.DropSpikeThresholdPS
		}
		e.state.mu.RUnlock()
	}

	if dropPS >= thresh {
		e.Notify(AlertEvent{
			Key:      "ddos_spike",
			Category: "ddos_spike",
			Severity: AlertSeverityCritical,
			Title:    fmt.Sprintf("DDoS / Drop Spike Detected (%.1f drops/s)", dropPS),
			Message:  fmt.Sprintf("Combined L7 Shield + Kernel drop rate reached %.1f drops/s (threshold %.1f/s).", dropPS, thresh),
			Details: map[string]string{
				"Drop Rate": fmt.Sprintf("%.2f /s", dropPS),
				"Threshold": fmt.Sprintf("%.2f /s", thresh),
			},
		})
	}

	// Upstream unhealthy state transitions
	curBad := make(map[string]UpstreamHealthStatus, len(unhealthy))
	for _, u := range unhealthy {
		if !u.Healthy {
			curBad[u.Source+"|"+u.Address] = u
		}
	}
	var newlyBad []UpstreamHealthStatus
	e.mu.Lock()
	for k, u := range curBad {
		if !e.prevUnhealthy[k] {
			newlyBad = append(newlyBad, u)
		}
	}
	e.prevUnhealthy = make(map[string]bool, len(curBad))
	for k := range curBad {
		e.prevUnhealthy[k] = true
	}
	e.mu.Unlock()

	for _, u := range newlyBad {
		e.Notify(AlertEvent{
			Key:      "upstream:" + u.Address,
			Category: "upstream_unhealthy",
			Severity: AlertSeverityWarning,
			Host:     u.Target,
			Title:    fmt.Sprintf("Upstream Backend Unhealthy: %s", u.Address),
			Message:  fmt.Sprintf("%s upstream %s for %s is reporting failures (%d fails).", strings.ToUpper(u.Source), u.Address, u.Target, u.Fails),
			Details: map[string]string{
				"Source":  u.Source,
				"Target":  u.Target,
				"Address": u.Address,
				"Fails":   strconv.Itoa(u.Fails),
			},
		})
	}

	// Certificate expiry (<14 days) with 24h anti-spam cadence per domain
	now := e.now().UTC()
	for _, c := range certs {
		if !c.ExpiringSoon {
			continue
		}
		key := c.Source + ":" + c.Domain
		e.mu.Lock()
		lastAt := e.certAlertAt[key]
		shouldAlert := lastAt.IsZero() || now.Sub(lastAt) >= 24*time.Hour
		if shouldAlert {
			e.certAlertAt[key] = now
		}
		e.mu.Unlock()

		if shouldAlert {
			sev := AlertSeverityWarning
			if c.Expired || c.DaysRemaining <= 3 {
				sev = AlertSeverityCritical
			}
			e.Notify(AlertEvent{
				Key:      "cert_expiry:" + key,
				Category: "cert_expiry",
				Severity: sev,
				Host:     c.Domain,
				Title:    fmt.Sprintf("TLS Certificate Expiring Soon: %s (%.1f days left)", c.Domain, c.DaysRemaining),
				Message:  fmt.Sprintf("Certificate (%s) expires on %s.", c.Source, c.NotAfter.Format(time.RFC3339)),
				Details: map[string]string{
					"Domain":   c.Domain,
					"Source":   c.Source,
					"Issuer":   c.Issuer,
					"NotAfter": c.NotAfter.Format(time.RFC3339),
				},
			})
		}
	}
}

func validateHTTPWebhookURL(raw string, label string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
		return fmt.Errorf("%s không hợp lệ (phải là URL http:// hoặc https://)", label)
	}
	return nil
}

func validateAlertChannelsConfig(cfg *AlertChannelsConfig) error {
	if cfg == nil {
		return errors.New("alerts config is required")
	}
	cfg.TelegramBotToken = strings.TrimSpace(cfg.TelegramBotToken)
	cfg.TelegramChatID = strings.TrimSpace(cfg.TelegramChatID)
	cfg.DiscordWebhookURL = strings.TrimSpace(cfg.DiscordWebhookURL)
	cfg.WebhookURL = strings.TrimSpace(cfg.WebhookURL)
	cfg.WebhookSecret = strings.TrimSpace(cfg.WebhookSecret)

	if cfg.TelegramEnabled {
		if cfg.TelegramBotToken == "" {
			return errors.New("telegram_bot_token không được để trống khi bật Telegram")
		}
		if cfg.TelegramChatID == "" {
			return errors.New("telegram_chat_id không được để trống khi bật Telegram")
		}
	}
	if cfg.DiscordEnabled {
		if err := validateHTTPWebhookURL(cfg.DiscordWebhookURL, "discord_webhook_url"); err != nil {
			return err
		}
	}
	if cfg.WebhookEnabled {
		if err := validateHTTPWebhookURL(cfg.WebhookURL, "webhook_url"); err != nil {
			return err
		}
	}
	return nil
}

func severityBadgeEmoji(sev AlertSeverity) string {
	switch sev {
	case AlertSeverityCritical:
		return "🚨 CRITICAL"
	case AlertSeverityInfo:
		return "ℹ️ INFO"
	default:
		return "⚠️ WARNING"
	}
}

func alertHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

func postJSONAlert(ctx context.Context, targetURL string, payload any, headers map[string]string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vSafeGate-Alert/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := alertHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// TelegramAlertChannel delivers alerts via Telegram Bot API sendMessage.
type TelegramAlertChannel struct {
	botToken string
	chatID   string
	apiBase  string
}

func NewTelegramAlertChannel(botToken, chatID string) *TelegramAlertChannel {
	return &TelegramAlertChannel{
		botToken: strings.TrimSpace(botToken),
		chatID:   strings.TrimSpace(chatID),
		apiBase:  "https://api.telegram.org",
	}
}

func (c *TelegramAlertChannel) Name() string { return "telegram" }

func (c *TelegramAlertChannel) Send(ctx context.Context, subject string, events []AlertEvent) error {
	if c.botToken == "" || c.chatID == "" {
		return errors.New("thiếu Telegram Bot Token hoặc Chat ID")
	}
	var b strings.Builder
	b.WriteString("🛡 *vSafeGate Security Alert*\n")
	b.WriteString(fmt.Sprintf("*%s*\n\n", subject))
	for i, ev := range events {
		if i >= 10 {
			b.WriteString(fmt.Sprintf("... và %d sự kiện khác\n", len(events)-10))
			break
		}
		b.WriteString(fmt.Sprintf("%s *%s*\n", severityBadgeEmoji(ev.Severity), ev.Title))
		if ev.Host != "" {
			b.WriteString(fmt.Sprintf("Host: `%s`\n", ev.Host))
		}
		if ev.Message != "" {
			b.WriteString(fmt.Sprintf("%s\n", ev.Message))
		}
		for k, v := range ev.Details {
			b.WriteString(fmt.Sprintf("• %s: `%s`\n", k, v))
		}
		b.WriteString("\n")
	}
	base := strings.TrimRight(c.apiBase, "/")
	if base == "" {
		base = "https://api.telegram.org"
	}
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", base, url.PathEscape(c.botToken))
	return postJSONAlert(ctx, endpoint, map[string]any{
		"chat_id":                  c.chatID,
		"text":                     b.String(),
		"parse_mode":               "Markdown",
		"disable_web_page_preview": true,
	}, nil)
}

// DiscordAlertChannel delivers alerts as Discord Webhook embeds.
type DiscordAlertChannel struct {
	webhookURL string
}

func NewDiscordAlertChannel(webhookURL string) *DiscordAlertChannel {
	return &DiscordAlertChannel{webhookURL: strings.TrimSpace(webhookURL)}
}

func (c *DiscordAlertChannel) Name() string { return "discord" }

func (c *DiscordAlertChannel) Send(ctx context.Context, subject string, events []AlertEvent) error {
	if err := validateHTTPWebhookURL(c.webhookURL, "discord_webhook_url"); err != nil {
		return err
	}
	embeds := make([]map[string]any, 0, len(events))
	for i, ev := range events {
		if i >= 10 {
			break
		}
		color := 15105570 // amber warning
		if ev.Severity == AlertSeverityCritical {
			color = 15158332 // red
		} else if ev.Severity == AlertSeverityInfo {
			color = 3447003 // blue
		}
		fields := make([]map[string]any, 0, len(ev.Details)+2)
		if ev.Category != "" {
			fields = append(fields, map[string]any{"name": "Category", "value": ev.Category, "inline": true})
		}
		if ev.Host != "" {
			fields = append(fields, map[string]any{"name": "Host", "value": ev.Host, "inline": true})
		}
		for k, v := range ev.Details {
			fields = append(fields, map[string]any{"name": k, "value": v, "inline": true})
		}
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		embeds = append(embeds, map[string]any{
			"title":       fmt.Sprintf("%s — %s", severityBadgeEmoji(ev.Severity), ev.Title),
			"description": ev.Message,
			"color":       color,
			"fields":      fields,
			"timestamp":   ts.UTC().Format(time.RFC3339),
		})
	}
	return postJSONAlert(ctx, c.webhookURL, map[string]any{
		"username": "vSafeGate SOC",
		"content":  fmt.Sprintf("**%s**", subject),
		"embeds":   embeds,
	}, nil)
}

// WebhookAlertChannel delivers structured JSON events with optional HMAC-SHA256 signature.
type WebhookAlertChannel struct {
	webhookURL string
	secret     string
}

func NewWebhookAlertChannel(webhookURL, secret string) *WebhookAlertChannel {
	return &WebhookAlertChannel{
		webhookURL: strings.TrimSpace(webhookURL),
		secret:     strings.TrimSpace(secret),
	}
}

func (c *WebhookAlertChannel) Name() string { return "webhook" }

func (c *WebhookAlertChannel) Send(ctx context.Context, subject string, events []AlertEvent) error {
	if err := validateHTTPWebhookURL(c.webhookURL, "webhook_url"); err != nil {
		return err
	}
	payload := map[string]any{
		"event":     "vsafegate_alert",
		"subject":   subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"count":     len(events),
		"events":    events,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	headers := map[string]string{}
	if c.secret != "" {
		mac := hmac.New(sha256.New, []byte(c.secret))
		mac.Write(raw)
		headers["X-vSafeGate-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vSafeGate-Alert/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := alertHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (e *AlertEngine) SendTestChannel(ctx context.Context, channel string, override *AlertChannelsConfig) error {
	var cfg AlertChannelsConfig
	if e != nil && e.state != nil {
		e.state.mu.RLock()
		cfg = e.state.config.Alerts
		e.state.mu.RUnlock()
	}
	if override != nil {
		merged := *override
		if strings.TrimSpace(merged.TelegramBotToken) == "" || merged.TelegramBotToken == "********" {
			merged.TelegramBotToken = cfg.TelegramBotToken
		}
		if strings.TrimSpace(merged.TelegramChatID) == "" {
			merged.TelegramChatID = cfg.TelegramChatID
		}
		if strings.TrimSpace(merged.DiscordWebhookURL) == "" {
			merged.DiscordWebhookURL = cfg.DiscordWebhookURL
		}
		if strings.TrimSpace(merged.WebhookURL) == "" {
			merged.WebhookURL = cfg.WebhookURL
		}
		if strings.TrimSpace(merged.WebhookSecret) == "" || merged.WebhookSecret == "********" {
			merged.WebhookSecret = cfg.WebhookSecret
		}
		cfg = merged
	}
	ev := AlertEvent{
		Key:       "channel_test:" + channel,
		Category:  "test",
		Severity:  AlertSeverityInfo,
		Title:     "vSafeGate Test Alert (" + strings.ToUpper(channel) + ")",
		Message:   "Đây là thông báo kiểm tra kênh cảnh báo từ vSafeGate Security Gateway.",
		Timestamp: time.Now().UTC(),
		Details: map[string]string{
			"Channel": channel,
			"Status":  "Connected",
		},
	}
	subject := "[vSafeGate] Test Alert — " + strings.ToUpper(channel)
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case "telegram":
		return NewTelegramAlertChannel(cfg.TelegramBotToken, cfg.TelegramChatID).Send(ctx, subject, []AlertEvent{ev})
	case "discord":
		return NewDiscordAlertChannel(cfg.DiscordWebhookURL).Send(ctx, subject, []AlertEvent{ev})
	case "webhook":
		return NewWebhookAlertChannel(cfg.WebhookURL, cfg.WebhookSecret).Send(ctx, subject, []AlertEvent{ev})
	default:
		return fmt.Errorf("kênh cảnh báo không hợp lệ: %s", channel)
	}
}
