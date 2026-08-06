package clog

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatsRecordAsSentence(t *testing.T) {
	var buf bytes.Buffer
	slog.New(New(&buf, slog.LevelInfo)).Info("listening on 127.0.0.1:7391")

	line := strings.TrimRight(buf.String(), "\n")
	require.Regexp(t, `^\d{2}:\d{2}:\d{2} INFO  listening on 127\.0\.0\.1:7391$`, line)
	require.NotContains(t, line, "=", "the console format must not emit key=value pairs")
	require.NotContains(t, line, "msg")
}

func TestLevelsArePaddedToAlign(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(New(&buf, slog.LevelDebug))
	log.Debug("one")
	log.Info("two")
	log.Warn("three")
	log.Error("four")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	require.Len(t, lines, 4)
	for _, line := range lines {
		// "15:04:05 LEVEL " is a fixed 15-column prefix.
		require.Equal(t, 15, strings.Index(line, strings.Fields(line)[2]), "line %q is misaligned", line)
	}
}

func TestDiscardsRecordsBelowLevel(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(New(&buf, slog.LevelInfo))
	log.Debug("hidden")
	require.Empty(t, buf.String())

	log.Warn("shown")
	require.Contains(t, buf.String(), "shown")
}

func TestRendersAttributeValuesWithoutKeys(t *testing.T) {
	var buf bytes.Buffer
	slog.New(New(&buf, slog.LevelInfo)).Info("could not report exit", "error", errors.New("broken pipe"))

	require.Contains(t, buf.String(), "could not report exit (broken pipe)")
	require.NotContains(t, buf.String(), "error=")
}

func TestWithAttrsPrefixesEveryRecord(t *testing.T) {
	var buf bytes.Buffer
	slog.New(New(&buf, slog.LevelInfo)).With("peer", "127.0.0.1:5555").Info("started")

	require.Contains(t, buf.String(), "started (127.0.0.1:5555)")
}

func TestSkipsEmptyAttributes(t *testing.T) {
	var buf bytes.Buffer
	slog.New(New(&buf, slog.LevelInfo)).Info("finished", "message", "")

	require.Contains(t, buf.String(), "finished\n", "an empty value must not leave dangling parentheses")
}

// Derived handlers share the parent's mutex, so lines from concurrent sessions
// must not interleave.
func TestConcurrentWritesProduceWholeLines(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(New(&buf, slog.LevelInfo))

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base.With("peer", "peer").Info(strings.Repeat("x", 64))
			_ = i
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	require.Len(t, lines, 50)
	for _, line := range lines {
		require.Regexp(t, `^\d{2}:\d{2}:\d{2} INFO  x{64} \(peer\)$`, line)
	}
}
