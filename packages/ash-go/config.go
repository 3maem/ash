// Package ash provides configuration utilities for ASH SDK (v2.3.4).
//
// This file adds environment-based configuration and proxy support.
package ash

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// AshConfig holds ASH SDK configuration from environment variables.
type AshConfig struct {
	TrustProxy         bool
	TrustedProxies     []string
	RateLimitWindow    int
	RateLimitMax       int
	TimestampTolerance int
}

var cachedConfig *AshConfig

// LoadConfig loads configuration from environment variables.
// v2.3.4: Added support for proxy and rate limiting configuration.
func LoadConfig() *AshConfig {
	if cachedConfig != nil {
		return cachedConfig
	}

	cachedConfig = &AshConfig{
		TrustProxy:         parseBool(os.Getenv("ASH_TRUST_PROXY")),
		TrustedProxies:     parseProxyList(os.Getenv("ASH_TRUSTED_PROXIES")),
		RateLimitWindow:    parseInt(os.Getenv("ASH_RATE_LIMIT_WINDOW"), 60),
		RateLimitMax:       parseInt(os.Getenv("ASH_RATE_LIMIT_MAX"), 10),
		TimestampTolerance: parseInt(os.Getenv("ASH_TIMESTAMP_TOLERANCE"), 30),
	}

	return cachedConfig
}

// ResetConfig resets the cached configuration (useful for testing).
func ResetConfig() {
	cachedConfig = nil
}

// parseBool parses a string as boolean.
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes" || s == "on"
}

// parseInt parses a string as integer with a default value.
func parseInt(s string, defaultVal int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return val
}

// parseProxyList parses a comma-separated list of proxy IPs.
func parseProxyList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// GetClientIP extracts the client IP address from HTTP headers.
// v2.3.4: Added X-Forwarded-For handling for deployments behind proxies/CDNs.
//
// Usage:
//
//	ip := ash.GetClientIP(r.Header.Get("X-Forwarded-For"), r.RemoteAddr)
func GetClientIP(forwardedFor, realIP, remoteAddr string) string {
	config := LoadConfig()

	// If not trusting proxies, use direct connection IP
	if !config.TrustProxy {
		return remoteAddr
	}

	// Check for X-Forwarded-For header
	if forwardedFor != "" {
		// Take the first IP in the chain
		parts := strings.Split(forwardedFor, ",")
		clientIP := strings.TrimSpace(parts[0])
		if isValidIP(clientIP) {
			return clientIP
		}
	}

	// Check for X-Real-IP header
	if realIP != "" {
		realIP = strings.TrimSpace(realIP)
		if isValidIP(realIP) {
			return realIP
		}
	}

	// Fall back to direct connection IP
	return remoteAddr
}

// isValidIP performs proper IP address validation using net.ParseIP.
func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	// Use net.ParseIP for proper validation
	parsed := net.ParseIP(ip)
	return parsed != nil
}
