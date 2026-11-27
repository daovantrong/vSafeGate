// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
// Patched by vSafeGate: shared refcounted mutex-protected AuditLogWriter with log-rotation reopen & FD leak fix.

package auditlog

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type sharedFileKey struct {
	target string
	mode   os.FileMode
}

type sharedFileEntry struct {
	key  sharedFileKey
	mu   sync.Mutex
	file *os.File
	info os.FileInfo
	refs int
}

var (
	sharedFilesMu sync.Mutex
	sharedFiles   = make(map[sharedFileKey]*sharedFileEntry)
	stdStreamMu   sync.Mutex
)

func acquireSharedFile(target string, fileMode, dirMode os.FileMode) (*sharedFileEntry, error) {
	if fileMode == 0 {
		fileMode = 0640
	}
	if dirMode == 0 {
		dirMode = 0755
	}
	cleanTarget := filepath.Clean(target)
	key := sharedFileKey{target: cleanTarget, mode: fileMode}

	sharedFilesMu.Lock()
	defer sharedFilesMu.Unlock()

	if entry, ok := sharedFiles[key]; ok {
		entry.refs++
		return entry, nil
	}

	if dir := filepath.Dir(cleanTarget); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, dirMode)
	}
	ff, err := os.OpenFile(cleanTarget, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return nil, err
	}
	info, _ := ff.Stat()
	entry := &sharedFileEntry{
		key:  key,
		file: ff,
		info: info,
		refs: 1,
	}
	sharedFiles[key] = entry
	return entry, nil
}

func (e *sharedFileEntry) writeLine(line []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.file == nil {
		ff, err := os.OpenFile(e.key.target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, e.key.mode)
		if err != nil {
			return err
		}
		e.file = ff
		e.info, _ = ff.Stat()
	} else if st, err := os.Stat(e.key.target); err == nil {
		if e.info == nil || !os.SameFile(st, e.info) {
			_ = e.file.Close()
			ff, errOpen := os.OpenFile(e.key.target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, e.key.mode)
			if errOpen != nil {
				e.file = nil
				e.info = nil
				return errOpen
			}
			e.file = ff
			e.info, _ = ff.Stat()
		}
	}

	buf := make([]byte, len(line)+1)
	copy(buf, line)
	buf[len(line)] = '\n'
	_, err := e.file.Write(buf)
	return err
}

func (e *sharedFileEntry) release() error {
	sharedFilesMu.Lock()
	defer sharedFilesMu.Unlock()

	e.refs--
	if e.refs > 0 {
		return nil
	}
	delete(sharedFiles, e.key)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil {
		return nil
	}
	err := e.file.Close()
	e.file = nil
	e.info = nil
	return err
}

// serialWriter is used to store logs in a single file safely across concurrent WAF instances.
type serialWriter struct {
	io.Closer
	stream    io.Writer
	entry     *sharedFileEntry
	closeOnce sync.Once
	formatter plugintypes.AuditLogFormatter
}

func (sl *serialWriter) Init(c plugintypes.AuditLogConfig) error {
	sl.Closer = NoopCloser
	if c.Target == "" {
		return nil
	}

	switch c.Target {
	case "/dev/stdout":
		sl.stream = os.Stdout
	case "/dev/stderr":
		sl.stream = os.Stderr
	default:
		entry, err := acquireSharedFile(c.Target, c.FileMode, c.DirMode)
		if err != nil {
			return err
		}
		sl.entry = entry
	}

	sl.formatter = c.Formatter
	return nil
}

func (sl *serialWriter) Write(al plugintypes.AuditLog) error {
	if sl.formatter == nil {
		return nil
	}

	bts, err := sl.formatter.Format(al)
	if err != nil {
		return err
	}

	if len(bts) == 0 {
		return nil
	}

	if sl.entry != nil {
		return sl.entry.writeLine(bts)
	}
	if sl.stream != nil {
		buf := make([]byte, len(bts)+1)
		copy(buf, bts)
		buf[len(bts)] = '\n'
		stdStreamMu.Lock()
		_, err = sl.stream.Write(buf)
		stdStreamMu.Unlock()
		return err
	}
	return nil
}

func (sl *serialWriter) Close() error {
	var err error
	sl.closeOnce.Do(func() {
		if sl.entry != nil {
			err = sl.entry.release()
			sl.entry = nil
			return
		}
		if sl.Closer != nil {
			err = sl.Closer.Close()
		}
	})
	return err
}

var _ plugintypes.AuditLogWriter = (*serialWriter)(nil)
