package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type LogPartitionMeta struct {
	FileName string         `json:"file_name"`
	HourKey  string         `json:"hour_key"`
	Count    int            `json:"count"`
	Bytes    int64          `json:"bytes"`
	MinTS    time.Time      `json:"min_ts,omitempty"`
	MaxTS    time.Time      `json:"max_ts,omitempty"`
	Actions  map[string]int `json:"actions,omitempty"`
}

type LogSummaryIndex struct {
	Version    int                          `json:"version"`
	UpdatedAt  time.Time                    `json:"updated_at"`
	Partitions map[string]*LogPartitionMeta `json:"partitions"`
}

type PersistentLogManager struct {
	mu             sync.Mutex
	filePath       string
	dir            string
	prefix         string
	ext            string
	indexPath      string
	maxBytes       int64
	retentionDays  int
	maxDiskBytes   int64
	index          *LogSummaryIndex
	appendOps      int
	lastActiveFile string
	nowFn          func() time.Time
}

func NewPersistentLogManager(path string, maxBytes int64) *PersistentLogManager {
	if maxBytes <= 0 {
		maxBytes = 20 * 1024 * 1024 // 20 MB legacy default hint
	}
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0750)

	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext == "" {
		ext = ".jsonl"
	}
	prefix := strings.TrimSuffix(base, ext)
	if prefix == "" {
		prefix = "attacks"
	}

	m := &PersistentLogManager{
		filePath:      path,
		dir:           dir,
		prefix:        prefix,
		ext:           ext,
		indexPath:     filepath.Join(dir, prefix+"-index.json"),
		maxBytes:      maxBytes,
		retentionDays: 30,
		maxDiskBytes:  512 * 1024 * 1024, // 512 MB default total disk cap
		nowFn:         time.Now,
	}
	m.loadAndReconcileIndexLocked()
	return m
}

func NewPartitionedLogManager(path string, retentionDays int, maxDiskMB int) *PersistentLogManager {
	m := NewPersistentLogManager(path, 20*1024*1024)
	m.ConfigureRetention(retentionDays, maxDiskMB)
	return m
}

func (m *PersistentLogManager) ConfigureRetention(retentionDays int, maxDiskMB int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if retentionDays > 0 {
		m.retentionDays = retentionDays
	}
	if maxDiskMB > 0 {
		m.maxDiskBytes = int64(maxDiskMB) * 1024 * 1024
	}
	m.enforceRetentionLocked()
}

func (m *PersistentLogManager) now() time.Time {
	if m.nowFn != nil {
		return m.nowFn()
	}
	return time.Now()
}

func (m *PersistentLogManager) partitionFileName(ts time.Time) string {
	return m.prefix + "-" + ts.UTC().Format("2006-01-02-15") + m.ext
}

func (m *PersistentLogManager) parsePartitionHour(name string) (time.Time, string, bool) {
	if !strings.HasPrefix(name, m.prefix+"-") || !strings.HasSuffix(name, m.ext) {
		return time.Time{}, "", false
	}
	key := strings.TrimSuffix(strings.TrimPrefix(name, m.prefix+"-"), m.ext)
	// Hourly format YYYY-MM-DD-HH (len 13) or daily YYYY-MM-DD (len 10)
	if len(key) == 13 {
		if t, err := time.Parse("2006-01-02-15", key); err == nil {
			return t.UTC(), key, true
		}
	} else if len(key) == 10 {
		if t, err := time.Parse("2006-01-02", key); err == nil {
			return t.UTC(), key, true
		}
	}
	return time.Time{}, "", false
}

// listLogFilesChronologicalLocked returns all legacy and partitioned log files sorted oldest -> newest.
func (m *PersistentLogManager) listLogFilesChronologicalLocked() []string {
	var files []string

	// Include any legacy non-partitioned files first if they exist and are non-empty
	legacyOrder := []string{
		m.filePath + ".3",
		m.filePath + ".2",
		m.filePath + ".1",
		m.filePath,
	}
	for _, p := range legacyOrder {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Size() > 0 {
			files = append(files, p)
		}
	}

	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return files
	}
	var partNames []string
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		if _, _, ok := m.parsePartitionHour(de.Name()); ok {
			partNames = append(partNames, de.Name())
		}
	}
	sort.Strings(partNames)
	for _, name := range partNames {
		files = append(files, filepath.Join(m.dir, name))
	}
	return files
}

func scanPartitionMeta(fullPath, fileName, hourKey string, size int64) *LogPartitionMeta {
	meta := &LogPartitionMeta{
		FileName: fileName,
		HourKey:  hourKey,
		Bytes:    size,
		Actions:  make(map[string]int),
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return meta
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		meta.Count++
		var entry AttackLog
		if json.Unmarshal([]byte(line), &entry) == nil {
			if !entry.Timestamp.IsZero() {
				if meta.MinTS.IsZero() || entry.Timestamp.Before(meta.MinTS) {
					meta.MinTS = entry.Timestamp
				}
				if meta.MaxTS.IsZero() || entry.Timestamp.After(meta.MaxTS) {
					meta.MaxTS = entry.Timestamp
				}
			}
			if entry.Action != "" {
				meta.Actions[entry.Action]++
			}
		}
	}
	return meta
}

func (m *PersistentLogManager) loadAndReconcileIndexLocked() {
	idx := &LogSummaryIndex{
		Version:    1,
		UpdatedAt:  m.now().UTC(),
		Partitions: make(map[string]*LogPartitionMeta),
	}
	if data, err := os.ReadFile(m.indexPath); err == nil {
		var parsed LogSummaryIndex
		if json.Unmarshal(data, &parsed) == nil && parsed.Partitions != nil {
			idx = &parsed
		}
	}

	present := make(map[string]struct{})
	dirty := false
	for _, fullPath := range m.listLogFilesChronologicalLocked() {
		name := filepath.Base(fullPath)
		present[name] = struct{}{}
		fi, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		_, hourKey, ok := m.parsePartitionHour(name)
		if !ok {
			hourKey = "legacy"
		}
		existing, exists := idx.Partitions[name]
		if !exists || existing == nil || existing.Bytes != fi.Size() {
			idx.Partitions[name] = scanPartitionMeta(fullPath, name, hourKey, fi.Size())
			dirty = true
		}
	}
	for k := range idx.Partitions {
		if _, ok := present[k]; !ok {
			delete(idx.Partitions, k)
			dirty = true
		}
	}

	m.index = idx
	if dirty {
		m.saveIndexLocked()
	}
}

func (m *PersistentLogManager) saveIndexLocked() {
	if m.index == nil {
		return
	}
	m.index.UpdatedAt = m.now().UTC()
	data, err := json.MarshalIndent(m.index, "", "  ")
	if err != nil {
		return
	}
	tmp := m.indexPath + ".tmp"
	if os.WriteFile(tmp, data, 0600) == nil {
		if os.Rename(tmp, m.indexPath) == nil {
			_ = os.Chmod(m.indexPath, 0600)
		}
	}
}

func (m *PersistentLogManager) Append(logEntry AttackLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if logEntry.Timestamp.IsZero() {
		logEntry.Timestamp = m.now().UTC()
	}

	data, err := json.Marshal(logEntry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	_ = os.MkdirAll(m.dir, 0750)
	fileName := m.partitionFileName(logEntry.Timestamp)
	fullPath := filepath.Join(m.dir, fileName)

	f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	_ = f.Close()
	if werr != nil {
		return werr
	}

	if m.index == nil {
		m.index = &LogSummaryIndex{Version: 1, Partitions: make(map[string]*LogPartitionMeta)}
	}
	meta, ok := m.index.Partitions[fileName]
	if !ok || meta == nil {
		_, hk, _ := m.parsePartitionHour(fileName)
		meta = &LogPartitionMeta{
			FileName: fileName,
			HourKey:  hk,
			Actions:  make(map[string]int),
		}
		m.index.Partitions[fileName] = meta
	}
	meta.Count++
	meta.Bytes += int64(len(data))
	if meta.MinTS.IsZero() || logEntry.Timestamp.Before(meta.MinTS) {
		meta.MinTS = logEntry.Timestamp
	}
	if meta.MaxTS.IsZero() || logEntry.Timestamp.After(meta.MaxTS) {
		meta.MaxTS = logEntry.Timestamp
	}
	if logEntry.Action != "" {
		if meta.Actions == nil {
			meta.Actions = make(map[string]int)
		}
		meta.Actions[logEntry.Action]++
	}

	switchedHour := m.lastActiveFile != "" && m.lastActiveFile != fileName
	m.lastActiveFile = fileName
	m.appendOps++

	if switchedHour || m.appendOps%25 == 0 {
		m.enforceRetentionLocked()
		m.saveIndexLocked()
	}
	return nil
}

func (m *PersistentLogManager) FlushIndex() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveIndexLocked()
}

func (m *PersistentLogManager) EnforceRetention() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enforceRetentionLocked()
}

func (m *PersistentLogManager) enforceRetentionLocked() {
	files := m.listLogFilesChronologicalLocked()
	if len(files) == 0 {
		return
	}

	now := m.now().UTC()
	cutoff := now.Add(-time.Duration(m.retentionDays) * 24 * time.Hour)
	changed := false

	// 1. Time-based retention cleanup
	if m.retentionDays > 0 {
		var kept []string
		for _, fullPath := range files {
			name := filepath.Base(fullPath)
			partTS, _, ok := m.parsePartitionHour(name)
			expired := false
			if ok {
				partEnd := partTS.Add(time.Hour)
				if len(strings.TrimSuffix(strings.TrimPrefix(name, m.prefix+"-"), m.ext)) == 10 {
					partEnd = partTS.Add(24 * time.Hour)
				}
				if partEnd.Before(cutoff) {
					expired = true
				}
			} else if fi, err := os.Stat(fullPath); err == nil && fi.ModTime().UTC().Before(cutoff) {
				expired = true
			}

			if expired {
				_ = os.Remove(fullPath)
				if m.index != nil {
					delete(m.index.Partitions, name)
				}
				changed = true
			} else {
				kept = append(kept, fullPath)
			}
		}
		files = kept
	}

	// 2. Total disk size cap cleanup (delete oldest partitions first, keeping newest active file)
	if m.maxDiskBytes > 0 && len(files) > 1 {
		sizes := make([]int64, len(files))
		var totalBytes int64
		for i, fullPath := range files {
			if fi, err := os.Stat(fullPath); err == nil {
				sizes[i] = fi.Size()
				totalBytes += fi.Size()
			}
		}
		for i := 0; i < len(files)-1 && totalBytes > m.maxDiskBytes; i++ {
			_ = os.Remove(files[i])
			totalBytes -= sizes[i]
			if m.index != nil {
				delete(m.index.Partitions, filepath.Base(files[i]))
			}
			changed = true
		}
	}

	if changed {
		m.saveIndexLocked()
	}
}

func (m *PersistentLogManager) SummaryIndex() LogSummaryIndex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.index == nil {
		m.loadAndReconcileIndexLocked()
	}
	out := LogSummaryIndex{
		Version:    m.index.Version,
		UpdatedAt:  m.index.UpdatedAt,
		Partitions: make(map[string]*LogPartitionMeta, len(m.index.Partitions)),
	}
	for k, v := range m.index.Partitions {
		cp := *v
		if v.Actions != nil {
			cp.Actions = make(map[string]int, len(v.Actions))
			for ak, av := range v.Actions {
				cp.Actions[ak] = av
			}
		}
		out.Partitions[k] = &cp
	}
	return out
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

	files := m.listLogFilesChronologicalLocked()
	result := make([]AttackLog, 0, limit)
	for fi := len(files) - 1; fi >= 0 && len(result) < limit; fi-- {
		entries := readEntriesFromFile(files[fi])
		for i := len(entries) - 1; i >= 0 && len(result) < limit; i-- {
			result = append(result, entries[i])
		}
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
	files := m.listLogFilesChronologicalLocked()

	// Fast path: no search filter -> read newest partitions backwards and stop once offset+limit is filled
	if searchLower == "" {
		total := m.totalCountLocked()
		needed := offset + limit
		reversed := make([]AttackLog, 0, min(needed, total))

		for fi := len(files) - 1; fi >= 0 && len(reversed) < needed; fi-- {
			entries := readEntriesFromFile(files[fi])
			for i := len(entries) - 1; i >= 0; i-- {
				reversed = append(reversed, entries[i])
				if len(reversed) >= needed {
					break
				}
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

	// Filtered search path (newest partition first)
	var matched []AttackLog
	for fi := len(files) - 1; fi >= 0; fi-- {
		entries := readEntriesFromFile(files[fi])
		for i := len(entries) - 1; i >= 0; i-- {
			entry := entries[i]
			if !strings.Contains(strings.ToLower(entry.ClientIP), searchLower) &&
				!strings.Contains(strings.ToLower(entry.Host), searchLower) &&
				!strings.Contains(strings.ToLower(entry.URI), searchLower) &&
				!strings.Contains(strings.ToLower(entry.RuleName), searchLower) &&
				!strings.Contains(strings.ToLower(entry.Action), searchLower) &&
				!strings.Contains(strings.ToLower(entry.UserAgent), searchLower) &&
				!strings.Contains(strings.ToLower(entry.MatchedVar), searchLower) &&
				!strings.Contains(strconv.Itoa(entry.RuleID), searchLower) {
				continue
			}
			matched = append(matched, entry)
		}
	}

	totalMatched := len(matched)
	start := offset
	if start > totalMatched {
		start = totalMatched
	}
	end := start + limit
	if end > totalMatched {
		end = totalMatched
	}
	return matched[start:end], totalMatched, nil
}

func (m *PersistentLogManager) totalCountLocked() int {
	if m.index != nil {
		total := 0
		for _, meta := range m.index.Partitions {
			if meta != nil {
				total += meta.Count
			}
		}
		return total
	}
	m.loadAndReconcileIndexLocked()
	total := 0
	for _, meta := range m.index.Partitions {
		if meta != nil {
			total += meta.Count
		}
	}
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

	for _, fullPath := range m.listLogFilesChronologicalLocked() {
		_ = os.Remove(fullPath)
	}
	for _, legacy := range []string{m.filePath, m.filePath + ".1", m.filePath + ".2", m.filePath + ".3", m.indexPath} {
		_ = os.Remove(legacy)
	}
	m.index = &LogSummaryIndex{
		Version:    1,
		UpdatedAt:  m.now().UTC(),
		Partitions: make(map[string]*LogPartitionMeta),
	}
	m.saveIndexLocked()
	return nil
}

func (m *PersistentLogManager) Export(w io.Writer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.listLogFilesChronologicalLocked() {
		if f, err := os.Open(p); err == nil {
			_, _ = io.Copy(w, f)
			_ = f.Close()
		}
	}
	return nil
}
