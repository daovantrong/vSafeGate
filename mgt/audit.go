package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type AdminAuditLogger struct {
	mu       sync.Mutex
	filePath string
	maxBytes int64
}

func NewAdminAuditLogger(path string) *AdminAuditLogger {
	if strings.TrimSpace(path) == "" {
		if os.Getenv("ENV") == "dev" {
			path = "./audit.jsonl"
		} else {
			path = "/var/log/vsafegate/audit.jsonl"
		}
	}
	_ = os.MkdirAll(filepath.Dir(path), 0750)
	return &AdminAuditLogger{
		filePath: path,
		maxBytes: 10 * 1024 * 1024,
	}
}

func (a *AdminAuditLogger) Record(actor, sourceIP, action, target, status, detail string) {
	if a == nil {
		return
	}
	entry := AdminAuditEntry{
		ID:        fmt.Sprintf("aud-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Actor:     strings.TrimSpace(actor),
		SourceIP:  strings.TrimSpace(sourceIP),
		Action:    strings.TrimSpace(action),
		Target:    strings.TrimSpace(target),
		Status:    strings.TrimSpace(status),
		Detail:    strings.TrimSpace(detail),
	}
	if entry.Actor == "" {
		entry.Actor = "system"
	}
	if entry.Status == "" {
		entry.Status = "success"
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	_ = os.MkdirAll(filepath.Dir(a.filePath), 0750)
	if fi, err := os.Stat(a.filePath); err == nil && a.maxBytes > 0 && fi.Size()+int64(len(data)) > a.maxBytes {
		_ = os.Remove(a.filePath + ".2")
		_ = os.Rename(a.filePath+".1", a.filePath+".2")
		_ = os.Rename(a.filePath, a.filePath+".1")
	}

	f, err := os.OpenFile(a.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	_, _ = f.Write(data)
	_ = f.Close()
	_ = os.Chmod(a.filePath, 0600)
}

func readAuditFile(path string) []AdminAuditEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []AdminAuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 32*1024), 512*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AdminAuditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

func (a *AdminAuditLogger) Query(search string, limit, offset int) ([]AdminAuditEntry, int) {
	if a == nil {
		return nil, 0
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	searchLower := strings.ToLower(strings.TrimSpace(search))

	a.mu.Lock()
	defer a.mu.Unlock()

	var all []AdminAuditEntry
	for _, suffix := range []string{".2", ".1", ""} {
		all = append(all, readAuditFile(a.filePath+suffix)...)
	}

	matched := make([]AdminAuditEntry, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		if searchLower != "" {
			if !strings.Contains(strings.ToLower(e.Actor), searchLower) &&
				!strings.Contains(strings.ToLower(e.SourceIP), searchLower) &&
				!strings.Contains(strings.ToLower(e.Action), searchLower) &&
				!strings.Contains(strings.ToLower(e.Target), searchLower) &&
				!strings.Contains(strings.ToLower(e.Detail), searchLower) &&
				!strings.Contains(strings.ToLower(e.Status), searchLower) {
				continue
			}
		}
		matched = append(matched, e)
	}

	total := len(matched)
	start := min(offset, total)
	end := min(start+limit, total)
	return matched[start:end], total
}
