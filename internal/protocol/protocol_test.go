package protocol

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandshakeRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteHandshake(&buf))
	require.NoError(t, ReadHandshake(&buf))
}

func TestHandshakeRejectsForeignPeer(t *testing.T) {
	err := ReadHandshake(strings.NewReader("HTTP/"))
	require.ErrorIs(t, err, ErrNotSbxWarden)
}

func TestHandshakeRejectsOtherVersion(t *testing.T) {
	err := ReadHandshake(bytes.NewReader(append([]byte(magic), version+1)))
	require.ErrorIs(t, err, ErrVersionMismatch)
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	require.NoError(t, w.WriteJSON(KindStart, Start{Token: "t", Args: []string{"ls", "--all"}, TTY: true}))
	require.NoError(t, w.WriteFrame(KindStdout, []byte("hello")))
	require.NoError(t, w.WriteFrame(KindStdinClose, nil))
	require.NoError(t, w.WriteJSON(KindExit, Exit{Code: 7, Message: "boom"}))

	r := NewReader(&buf)

	frame, err := r.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, KindStart, frame.Kind)
	var start Start
	require.NoError(t, DecodeJSON(frame, &start))
	require.Equal(t, []string{"ls", "--all"}, start.Args)
	require.True(t, start.TTY)

	frame, err = r.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, KindStdout, frame.Kind)
	require.Equal(t, "hello", string(frame.Payload))

	frame, err = r.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, KindStdinClose, frame.Kind)
	require.Empty(t, frame.Payload)

	frame, err = r.ReadFrame()
	require.NoError(t, err)
	var exit Exit
	require.NoError(t, DecodeJSON(frame, &exit))
	require.Equal(t, 7, exit.Code)
	require.Equal(t, "boom", exit.Message)

	_, err = r.ReadFrame()
	require.ErrorIs(t, err, io.EOF)
}

func TestWriteFrameRejectsOversizePayload(t *testing.T) {
	err := NewWriter(io.Discard).WriteFrame(KindStdout, make([]byte, MaxPayload+1))
	require.ErrorIs(t, err, ErrPayloadTooLarge)
}

func TestReadFrameRejectsOversizeLength(t *testing.T) {
	header := []byte{byte(KindStdout), 0xff, 0xff, 0xff, 0xff}
	_, err := NewReader(bytes.NewReader(header)).ReadFrame()
	require.ErrorIs(t, err, ErrPayloadTooLarge)
}

func TestStreamSplitsAcrossFrames(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	payload := bytes.Repeat([]byte("x"), MaxPayload+512)
	n, err := w.Stream(KindStdout).Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	r := NewReader(&buf)
	var got []byte
	for range 2 {
		frame, err := r.ReadFrame()
		require.NoError(t, err)
		require.Equal(t, KindStdout, frame.Kind)
		got = append(got, frame.Payload...)
	}
	require.Equal(t, payload, got)

	_, err = r.ReadFrame()
	require.ErrorIs(t, err, io.EOF)
}

func TestReadFrameReportsTruncatedHeader(t *testing.T) {
	_, err := NewReader(bytes.NewReader([]byte{byte(KindStdout), 0x00})).ReadFrame()
	require.Error(t, err)
	require.False(t, errors.Is(err, io.EOF), "a partial header is a failure, not a clean end of stream")
}
