package tunnelserver

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const requestIDHeader = "X-Request-ID"

type requestMetadata struct {
	RequestID string
	TraceID   string
}

type contextKey string

const (
	loggerContextKey          contextKey = "logger"
	requestMetadataContextKey contextKey = "request-metadata"
)

func NewRequestLoggingMiddleware(baseLogger *slog.Logger, next http.Handler) http.Handler {
	if baseLogger == nil {
		baseLogger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := requestMetadata{
			RequestID: newLogID(),
			TraceID:   requestTraceID(r),
		}
		w.Header().Set(requestIDHeader, metadata.RequestID)

		logger := baseLogger.With(
			slog.String("request_id", metadata.RequestID),
			slog.String("trace_id", metadata.TraceID),
		)
		ctx := context.WithValue(r.Context(), loggerContextKey, logger)
		ctx = context.WithValue(ctx, requestMetadataContextKey, metadata)
		r = r.WithContext(ctx)

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(recorder, r)

		logger.Info("http_request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.status),
			slog.Int("bytes", recorder.bytes),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("remote_ip", requestRemoteIP(r)),
			slog.String("user_agent", r.UserAgent()),
		)
	})
}

func loggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerContextKey).(*slog.Logger); ok && logger != nil {
		return logger
	}
	return slog.Default()
}

func requestMetadataFromContext(ctx context.Context) requestMetadata {
	if metadata, ok := ctx.Value(requestMetadataContextKey).(requestMetadata); ok {
		return metadata
	}
	return requestMetadata{}
}

func newLogID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return hex.EncodeToString(buf[:])
	}
	return fmt.Sprintf("%016x", time.Now().UnixNano())
}

func requestTraceID(r *http.Request) string {
	if traceID := parseTraceparentTraceID(r.Header.Get("Traceparent")); traceID != "" {
		return traceID
	}
	return newLogID()
}

func parseTraceparentTraceID(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) != 4 {
		return ""
	}
	if len(parts[1]) != 32 || !isLowerHex(parts[1]) || parts[1] == strings.Repeat("0", 32) {
		return ""
	}
	return parts[1]
}

func isLowerHex(value string) bool {
	for _, ch := range value {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
}

func requestRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}
