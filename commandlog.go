package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type CommandLog struct {
	mu   sync.Mutex
	f    *os.File
	path string
	seq  uint64
}

var commandLog CommandLog
var commandLogStartTime = time.Now()

type commandLogFrame struct {
	Src     uint16 `json:"src,omitempty"`
	SrcHex  string `json:"src_hex,omitempty"`
	Dst     uint16 `json:"dst,omitempty"`
	DstHex  string `json:"dst_hex,omitempty"`
	Op      uint8  `json:"op,omitempty"`
	OpHex   string `json:"op_hex,omitempty"`
	OpName  string `json:"op_name,omitempty"`
	DataLen uint8  `json:"data_len,omitempty"`
	DataHex string `json:"data_hex,omitempty"`
}

type commandLogRecord struct {
	Timestamp string           `json:"ts"`
	UnixMs    int64            `json:"unix_ms"`
	Event     string           `json:"event"`
	Seq       uint64           `json:"seq"`
	Attempt   int              `json:"attempt"`
	ElapsedMs int64            `json:"elapsed_ms,omitempty"`
	RawHex    string           `json:"raw_hex,omitempty"`
	Request   *commandLogFrame `json:"request,omitempty"`
	Response  *commandLogFrame `json:"response,omitempty"`
	Note      string           `json:"note,omitempty"`
}

func autoCommandLogPath() string {
	return fmt.Sprintf("commandlog-%s.jsonl", commandLogStartTime.Format("20060102-150405"))
}

func startTimeCommandLogPath(requested string) string {
	path := strings.TrimSpace(requested)
	if path == "" {
		return autoCommandLogPath()
	}

	if st, err := os.Stat(path); err == nil && st.IsDir() {
		return filepath.Join(path, autoCommandLogPath())
	}

	if strings.HasSuffix(path, string(os.PathSeparator)) {
		return filepath.Join(path, autoCommandLogPath())
	}

	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	if ext == "" {
		ext = ".jsonl"
	}
	return fmt.Sprintf("%s-%s%s", base, commandLogStartTime.Format("20060102-150405"), ext)
}

func (c *CommandLog) Open(path string, rotate bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	var finalPath string
	var flags int

	var err error
	finalPath, err = nextCapturePath(startTimeCommandLogPath(path))
	if err != nil {
		log.Errorf("failed to select command log file '%s': %s", path, err)
		return false
	}
	flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL

	f, err := os.OpenFile(finalPath, flags, 0644)
	if err != nil {
		log.Errorf("failed to open command log file '%s': %s", finalPath, err)
		return false
	}

	if c.f != nil {
		_ = c.f.Close()
	}
	c.f = f
	c.path = finalPath
	log.Infof("Opened command log file '%s'", finalPath)
	return true
}

func (c *CommandLog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.f != nil {
		if err := c.f.Close(); err != nil {
			log.Warnf("error closing command log file '%s': %s", c.path, err)
		}
		c.f = nil
	}
}

func (c *CommandLog) NextSeq() uint64 {
	return atomic.AddUint64(&c.seq, 1)
}

func (c *CommandLog) Log(event string, seq uint64, attempt int, request *InfinityFrame, raw []byte, response *InfinityFrame, elapsed time.Duration, note string) {
	rec := commandLogRecord{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		UnixMs:    time.Now().UnixMilli(),
		Event:     event,
		Seq:       seq,
		Attempt:   attempt,
		ElapsedMs: elapsed.Milliseconds(),
		RawHex:    hex.EncodeToString(raw),
		Request:   commandLogRecordFrame(request),
		Response:  commandLogRecordFrame(response),
		Note:      note,
	}

	c.logRecord(rec)
}

func commandLogRecordFrame(frame *InfinityFrame) *commandLogFrame {
	if frame == nil {
		return nil
	}

	return &commandLogFrame{
		Src:     frame.src,
		SrcHex:  fmt.Sprintf("0x%04x", frame.src),
		Dst:     frame.dst,
		DstHex:  fmt.Sprintf("0x%04x", frame.dst),
		Op:      frame.op,
		OpHex:   fmt.Sprintf("0x%02x", frame.op),
		OpName:  frame.opString(),
		DataLen: frame.dataLen,
		DataHex: hex.EncodeToString(frame.data),
	}
}

func (c *CommandLog) logRecord(rec commandLogRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.f == nil {
		return
	}

	b, err := json.Marshal(rec)
	if err != nil {
		log.Errorf("command log json marshal failed: %s", err)
		return
	}
	b = append(b, '\n')

	if _, err = c.f.Write(b); err != nil {
		log.Errorf("command log write failed: %s", err)
	}
}
