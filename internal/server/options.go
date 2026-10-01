package server

import (
	"fmt"
	"time"
)

// ServerOptions contains the argument passed as environment variables that
// influence the server.
type ServerOptions struct {
	// Webhook host
	WebhookHost string `env:"WEBHOOK_HOST" default:"localhost"`
	// Webhook port
	WebhookPort uint16 `env:"WEBHOOK_PORT" default:"8888"`
	// Readiness and liveness probe host
	HealthHost string `env:"HEALTH_HOST" default:"0.0.0.0"`
	// Readiness and liveness probe port
	HealthPort uint16 `env:"HEALTH_PORT" default:"8080"`
	// Read timeout in milliseconds
	ReadTimeout int `env:"READ_TIMEOUT" default:"60000"`
	// Write timeout in milliseconds
	WriteTimeout int `env:"WRITE_TIMEOUT" default:"60000"`
	// Read header timeout in milliseconds
	ReadHeaderTimeout int `env:"READ_HEADER_TIMEOUT" default:"5000"`
	// Idle timeout in milliseconds
	IdleTimeout int `env:"IDLE_TIMEOUT" default:"60000"`
	// Maximum webhook request size in bytes
	MaxBodySize int64 `env:"MAX_BODY_SIZE" default:"1048576"`
}

// GetWebhookAddress returns the webhook address as "host:port".
func (o ServerOptions) GetWebhookAddress() string {
	return fmt.Sprintf("%s:%d", o.WebhookHost, o.WebhookPort)
}

// GetHealthAddress returns the address of the liveness and readiness probe as
// "host:port".
func (o ServerOptions) GetHealthAddress() string {
	return fmt.Sprintf("%s:%d", o.HealthHost, o.HealthPort)
}

// GetReadTimeout returns the read timeout in milliseconds.
func (o ServerOptions) GetReadTimeout() time.Duration {
	return time.Duration(o.ReadTimeout) * time.Millisecond
}

// GetWriteTimeout returns the read timeout in milliseconds.
func (o ServerOptions) GetWriteTimeout() time.Duration {
	return time.Duration(o.WriteTimeout) * time.Millisecond
}

// GetReadHeaderTimeout returns the read header timeout in milliseconds.
func (o ServerOptions) GetReadHeaderTimeout() time.Duration {
	return time.Duration(o.ReadHeaderTimeout) * time.Millisecond
}

// GetIdleTimeout returns the idle timeout in milliseconds.
func (o ServerOptions) GetIdleTimeout() time.Duration {
	return time.Duration(o.IdleTimeout) * time.Millisecond
}
