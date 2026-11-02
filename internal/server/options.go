package server

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// ServerOptions contains the argument passed as environment variables that
// influence the server.
type ServerOptions struct {
	// Webhook host
	WebhookHost string `env:"WEBHOOK_HOST" default:"localhost"`
	// Webhook port
	WebhookPort uint `env:"WEBHOOK_PORT" default:"8888"`
	// Readiness and liveness probe host
	HealthHost string `env:"HEALTH_HOST" default:"0.0.0.0"`
	// Readiness and liveness probe port
	HealthPort uint `env:"HEALTH_PORT" default:"8080"`
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

// Validate rejects ports that would otherwise wrap or bind an unintended port.
func (o ServerOptions) Validate() error {
	for name, port := range map[string]uint{"WEBHOOK_PORT": o.WebhookPort, "HEALTH_PORT": o.HealthPort} {
		if port == 0 || port > 65535 {
			return fmt.Errorf("%s must be between 1 and 65535", name)
		}
	}
	for name, timeout := range map[string]int{"READ_TIMEOUT": o.ReadTimeout, "WRITE_TIMEOUT": o.WriteTimeout, "READ_HEADER_TIMEOUT": o.ReadHeaderTimeout, "IDLE_TIMEOUT": o.IdleTimeout} {
		if timeout < 0 || int64(timeout) > int64((1<<63-1)/time.Millisecond) {
			return fmt.Errorf("%s must be a nonnegative duration representable in milliseconds", name)
		}
	}
	return nil
}

// GetWebhookAddress returns the webhook address as "host:port".
func (o ServerOptions) GetWebhookAddress() string {
	return net.JoinHostPort(o.WebhookHost, strconv.Itoa(int(o.WebhookPort)))
}

// GetHealthAddress returns the address of the liveness and readiness probe as
// "host:port".
func (o ServerOptions) GetHealthAddress() string {
	return net.JoinHostPort(o.HealthHost, strconv.Itoa(int(o.HealthPort)))
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
