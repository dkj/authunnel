// Package wsconn provides a net.Conn adapter for WebSocket connections that
// multiplexes control (text) and data (binary) message types. Text frames
// carry JSON control messages (token refresh, expiry warnings); binary frames
// carry the SOCKS5 data stream unchanged.
package wsconn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// ControlMessage is a JSON envelope sent over WebSocket text frames.
type ControlMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// MultiplexConn wraps a *websocket.Conn as a net.Conn for binary (SOCKS5) data,
// while routing text frames to a separate control channel.
type MultiplexConn struct {
	ws     *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc

	controlC  chan ControlMessage // incoming control messages
	closeOnce sync.Once          // guards controlC close
	reader    io.Reader          // partial binary message reader

	writeMu sync.Mutex // serializes all frame writes
}

// New creates a MultiplexConn from an already-upgraded WebSocket. The returned
// connection satisfies net.Conn for binary data. Control messages arriving as
// text frames are available via ControlChan.
func New(ctx context.Context, ws *websocket.Conn) *MultiplexConn {
	ctx, cancel := context.WithCancel(ctx)
	return &MultiplexConn{
		ws:       ws,
		ctx:      ctx,
		cancel:   cancel,
		controlC: make(chan ControlMessage, 8),
	}
}

// ControlChan returns a channel that receives incoming text-frame control messages.
func (c *MultiplexConn) ControlChan() <-chan ControlMessage {
	return c.controlC
}

// SendControl sends a control message as a WebSocket text frame.
func (c *MultiplexConn) SendControl(msg ControlMessage) error {
	return c.sendControlCtx(c.ctx, msg)
}

// SendControlTimeout sends a control message using an independent context with
// the given timeout. This is useful for best-effort writes after the main
// connection context has been cancelled (e.g. sending a disconnect frame
// during forced tunnel teardown).
func (c *MultiplexConn) SendControlTimeout(timeout time.Duration, msg ControlMessage) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.sendControlCtx(ctx, msg)
}

func (c *MultiplexConn) sendControlCtx(ctx context.Context, msg ControlMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal control message: %w", err)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.Write(ctx, websocket.MessageText, data)
}

// Read implements net.Conn. It returns only binary-frame data; text frames
// are dispatched to the control channel transparently.
func (c *MultiplexConn) Read(p []byte) (int, error) {
	for {
		// Drain any partial binary message from a previous Read call.
		if c.reader != nil {
			n, err := c.reader.Read(p)
			if err == io.EOF {
				c.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			return n, err
		}

		typ, reader, err := c.ws.Reader(c.ctx)
		if err != nil {
			c.closeOnce.Do(func() { close(c.controlC) })
			return 0, err
		}

		if typ == websocket.MessageBinary {
			c.reader = reader
			continue // loop back to read from it
		}

		// Text frame: consume fully and dispatch as control message.
		data, err := io.ReadAll(reader)
		if err != nil {
			c.closeOnce.Do(func() { close(c.controlC) })
			return 0, fmt.Errorf("read control frame: %w", err)
		}
		var msg ControlMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue // skip malformed control messages
		}
		select {
		case c.controlC <- msg:
		default:
			// Drop if channel is full to avoid blocking the data path.
		}
	}
}

// Write implements net.Conn. Data is sent as binary WebSocket frames.
func (c *MultiplexConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ws.Write(c.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close cancels the connection context and closes the underlying WebSocket.
// The control channel is closed by Read (the sole sender) when it observes
// the context cancellation, following the "sender closes" pattern.
func (c *MultiplexConn) Close() error {
	c.cancel()
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

// LocalAddr implements net.Conn.
func (c *MultiplexConn) LocalAddr() net.Addr { return wsAddr("websocket-local") }

// RemoteAddr implements net.Conn.
func (c *MultiplexConn) RemoteAddr() net.Addr { return wsAddr("websocket-remote") }

// SetDeadline implements net.Conn.
func (c *MultiplexConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline implements net.Conn.
func (c *MultiplexConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline implements net.Conn.
func (c *MultiplexConn) SetWriteDeadline(t time.Time) error { return nil }

type wsAddr string

func (a wsAddr) Network() string { return "websocket" }
func (a wsAddr) String() string  { return string(a) }
