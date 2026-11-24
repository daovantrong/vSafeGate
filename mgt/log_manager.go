package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type PersistentLogManager struct {
	mu          sync.Mutex
	filePath    string
	maxBytes    int64
	cachedCount int
}

func NewPersistentLogManager(path string, maxBytes int64) *PersistentLogManager {
	if maxBytes <= 0 {
		maxBytes = 20 * 1024 * 1024 // 20 MB default
	}
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	return &PersistentLogManager{
		filePath:    path,
		maxBytes:    maxBytes,
		cachedCount: -1,
	}
}

func (m *PersistentLogManager) Append(logEntry AttackLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := json.Marshal(logEntry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Check rotation
	if fi, err := os.Stat(m.filePath); err == nil && fi.Size()+int64(len(data)) > m.maxBytes {
		m.rotate()
	}

	f, err := os.OpenFile(m.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	if err == nil && m.cachedCount >= 0 {
		m.cachedCount++
	}
	return err
}

func (m *PersistentLogManager) rotate() {
	// Keep 3 backups: .1, .2, .3
	p := m.filePath
	os.Remove(p + ".3")
	os.Rename(p+".2", p+".3")
	os.Rename(p+".1", p+".2")
	os.Rename(p, p+".1")
	m.cachedCount = -1
}

func readEntriesFromFile(filePath string) []AttackLog {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []AttackLog
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry AttackLog
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries
}

func (m *PersistentLogManager) ReadRecent(limit int) ([]AttackLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 {
		limit = 100
	}

	// Read current file first
	currentLogs := readEntriesFromFile(m.filePath)
	
	// If needed more, read rotated files .1, .2, .3
	if len(currentLogs) < limit {
		rot1 := readEntriesFromFile(m.filePath + ".1")
		currentLogs = append(rot1, currentLogs...)
	}
	if len(currentLogs) < limit {
		rot2 := readEntriesFromFile(m.filePath + ".2")
		currentLogs = append(rot2, currentLogs...)
	}
	if len(currentLogs) < limit {
		rot3 := readEntriesFromFile(m.filePath + ".3")
		currentLogs = append(rot3, currentLogs...)
	}

	total := len(currentLogs)
	result := make([]AttackLog, 0, limit)
	for i := total - 1; i >= 0 && len(result) < limit; i-- {
		result = append(result, currentLogs[i])
	}
	return result, nil
}

func (m *PersistentLogManager) Query(search string, limit, offset int) ([]AttackLog, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 {
		limit = 50
	}
	if limit > 10000 {
		limit = 10000
	}
	if offset < 0 {
		offset = 0
	}

	searchLower := strings.ToLower(strings.TrimSpace(search))

	// Fast path: if no search query, read backwards from newest files and stop when we have enough for offset+limit
	if searchLower == "" {
		total := m.totalCountLocked()
		needed := offset + limit
		var reversed []AttackLog

		for _, suffix := range []string{"", ".1", ".2", ".3"} {
			entries := readEntriesFromFile(m.filePath + suffix)
			for i := len(entries) - 1; i >= 0; i-- {
				reversed = append(reversed, entries[i])
				if len(reversed) >= needed {
					break
				}
			}
			if len(reversed) >= needed {
				break
			}
		}

		start := offset
		if start > len(reversed) {
			start = len(reversed)
		}
		end := start + limit
		if end > len(reversed) {
			end = len(reversed)
		}

		return reversed[start:end], total, nil
	}

	// Filtered search path
	var allLogs []AttackLog
	allLogs = append(allLogs, readEntriesFromFile(m.filePath+".3")...)
	allLogs = append(allLogs, readEntriesFromFile(m.filePath+".2")...)
	allLogs = append(allLogs, readEntriesFromFile(m.filePath+".1")...)
	allLogs = append(allLogs, readEntriesFromFile(m.filePath)...)

	var matched []AttackLog
	for _, entry := range allLogs {
		if !strings.Contains(strings.ToLower(entry.ClientIP), searchLower) &&
			!strings.Contains(strings.ToLower(entry.Host), searchLower) &&
			!strings.Contains(strings.ToLower(entry.URI), searchLower) &&
			!strings.Contains(strings.ToLower(entry.RuleName), searchLower) &&
			!strings.Contains(strings.ToLower(entry.Action), searchLower) &&
			!strings.Contains(strings.ToLower(entry.UserAgent), searchLower) {
			continue
		}
		matched = append(matched, entry)
	}

	totalMatched := len(matched)
	// Reverse to most recent first
	reversed := make([]AttackLog, totalMatched)
	for i := 0; i < totalMatched; i++ {
		reversed[i] = matched[totalMatched-1-i]
	}

	start := offset
	if start > totalMatched {
		start = totalMatched
	}
	end := start + limit
	if end > totalMatched {
		end = totalMatched
	}

	return reversed[start:end], totalMatched, nil
}

func (m *PersistentLogManager) totalCountLocked() int {
	if m.cachedCount >= 0 {
		return m.cachedCount
	}
	total := 0
	for _, suffix := range []string{".3", ".2", ".1", ""} {
		p := m.filePath + suffix
		if f, err := os.Open(p); err == nil {
			scanner := bufio.NewScanner(f)
			buf := make([]byte, 64*1024)
			scanner.Buffer(buf, 1024*1024)
			for scanner.Scan() {
				if strings.TrimSpace(scanner.Text()) != "" {
					total++
				}
			}
			f.Close()
		}
	}
	m.cachedCount = total
	return total
}

func (m *PersistentLogManager) TotalCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalCountLocked()
}

func (m *PersistentLogManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Truncate file
	f, err := os.OpenFile(m.filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	f.Close()

	// Also remove backups
	p := m.filePath
	os.Remove(p + ".1")
	os.Remove(p + ".2")
	os.Remove(p + ".3")
	m.cachedCount = 0
	return nil
}

func (m *PersistentLogManager) Export(w io.Writer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, suffix := range []string{".3", ".2", ".1", ""} {
		p := m.filePath + suffix
		if f, err := os.Open(p); err == nil {
			io.Copy(w, f)
			f.Close()
		}
	}
	return nil
}
