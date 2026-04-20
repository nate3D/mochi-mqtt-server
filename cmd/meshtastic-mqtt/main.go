package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	meshhook "github.com/mochi-mqtt/server/v2/hooks/meshtastic"
	"github.com/mochi-mqtt/server/v2/listeners"
	"gopkg.in/yaml.v3"
)

// ANSI colour codes used by colorWriter.
const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiReset  = "\x1b[0m"
)

// colorWriter wraps an io.Writer and prepends ANSI colour codes to each log
// line based on the slog level field it contains:
//
//	DEBUG / INFO  → green
//	WARN          → yellow
//	ERROR         → red
//
// slog.TextHandler calls Write exactly once per log record, so each Write
// call received here is always a complete, newline-terminated line.
// Disable by setting NO_COLOR=1 or TERM=dumb in the environment.
type colorWriter struct{ out io.Writer }

func (w *colorWriter) Write(p []byte) (int, error) {
	color := ansiGreen
	switch {
	case bytes.Contains(p, []byte("level=ERROR")):
		color = ansiRed
	case bytes.Contains(p, []byte("level=WARN")):
		color = ansiYellow
	}
	line := bytes.TrimRight(p, "\n")
	out := make([]byte, 0, len(color)+len(line)+len(ansiReset)+1)
	out = append(out, color...)
	out = append(out, line...)
	out = append(out, ansiReset...)
	out = append(out, '\n')
	if _, err := w.out.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// filterHandler wraps a slog.Handler and suppresses known-noisy, benign
// log records emitted by the upstream mochi-mqtt listener code.
//
// Specifically it drops WARN records with an empty message whose sole
// structured field is error=EOF — these are produced whenever a client
// disconnects without sending a DISCONNECT packet, which is normal for
// IoT devices that power-cycle or lose connectivity.
type filterHandler struct{ slog.Handler }

func (f filterHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn && r.Message == "" {
		var isEOF bool
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "error" && strings.Contains(a.Value.String(), "EOF") {
				isEOF = true
				return false
			}
			return true
		})
		if isEOF {
			return nil
		}
	}
	return f.Handler.Handle(ctx, r)
}

func (f filterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return filterHandler{f.Handler.WithAttrs(attrs)}
}

func (f filterHandler) WithGroup(name string) slog.Handler {
	return filterHandler{f.Handler.WithGroup(name)}
}

// serverConfig is the top-level configuration file structure.
type serverConfig struct {
	// TCP listener address (plain MQTT). Default ":1883". Set empty to disable.
	TCPAddr string `yaml:"tcp_addr"`
	// TLSAddr is the address for TLS-encrypted MQTT (MQTTS). Default: disabled.
	TLSAddr string `yaml:"tls_addr"`
	// WSAddr is the address for WebSocket MQTT. Default: disabled.
	WSAddr string `yaml:"ws_addr"`
	// CertFile is the path to the PEM TLS certificate file.
	CertFile string `yaml:"cert_file"`
	// KeyFile is the path to the PEM TLS private key file.
	KeyFile string `yaml:"key_file"`
	// StatsAddr is the address for the HTTP stats endpoint (e.g. ":2112").
	// Leave empty to disable. The endpoint is served at GET /stats.
	StatsAddr string `yaml:"stats_addr"`
	// Meshtastic contains the Meshtastic hook configuration.
	Meshtastic meshtasticConfig `yaml:"meshtastic"`
}

// meshtasticConfig is the YAML representation of meshhook.Config with
// base64-encoded PSKs for human-readable config files.
type meshtasticConfig struct {
	Credentials        []credentialConfig       `yaml:"credentials"`
	Channels           []channelConfig          `yaml:"channels"`
	BlockedPortNums    []int32                  `yaml:"blocked_port_nums"`
	AllowedPortNums    []int32                  `yaml:"allowed_port_nums"`
	RateLimits         meshhook.RateLimitConfig `yaml:"rate_limits"`
	RequireDecryptable bool                     `yaml:"require_decryptable"`
	AllowJSON          bool                     `yaml:"allow_json"`
	AllowedRegions     []string                 `yaml:"allowed_regions"`
	UpstreamForward    upstreamForwardConfig    `yaml:"upstream_forward"`
}

// upstreamForwardConfig is the YAML representation of meshhook.UpstreamForwardConfig.
// The password can alternatively be supplied via UPSTREAM_MQTT_PASSWORD env var.
type upstreamForwardConfig struct {
	Enabled         bool     `yaml:"enabled"`
	BrokerAddr      string   `yaml:"broker_addr"`
	Username        string   `yaml:"username"`
	Password        string   `yaml:"password"`
	TLS             bool     `yaml:"tls"`
	ClientID        string   `yaml:"client_id"`
	Channels        []string `yaml:"channels"`
	BlockedChannels []string `yaml:"blocked_channels"`
}

// credentialConfig is a username + bcrypt password hash from the config file.
type credentialConfig struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// channelConfig represents a channel with a base64-encoded PSK for config files.
type channelConfig struct {
	Name   string `yaml:"name"`
	PSKB64 string `yaml:"psk_base64"` // base64-encoded raw PSK bytes
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to server config file")
	flag.Parse()

	logLevel := slog.LevelDebug
	switch strings.ToUpper(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	}

	useColor := os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	var logOut io.Writer = os.Stdout
	if useColor {
		logOut = &colorWriter{out: os.Stdout}
	}
	log := slog.New(filterHandler{slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: logLevel})})

	cfg, err := loadConfig(*configPath, log)
	if err != nil {
		log.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if cfg.TCPAddr == "" && cfg.TLSAddr == "" && cfg.WSAddr == "" {
		cfg.TCPAddr = ":1883"
	}

	server := mqtt.New(&mqtt.Options{
		Logger: log,
	})

	// Build the hook config, decoding base64 PSKs.
	hookCfg := meshhook.Config{
		BlockedPortNums:    cfg.Meshtastic.BlockedPortNums,
		AllowedPortNums:    cfg.Meshtastic.AllowedPortNums,
		RateLimits:         cfg.Meshtastic.RateLimits,
		RequireDecryptable: cfg.Meshtastic.RequireDecryptable,
		AllowJSON:          cfg.Meshtastic.AllowJSON,
		AllowedRegions:     cfg.Meshtastic.AllowedRegions,
		UpstreamForward: meshhook.UpstreamForwardConfig{
			Enabled:         cfg.Meshtastic.UpstreamForward.Enabled,
			BrokerAddr:      cfg.Meshtastic.UpstreamForward.BrokerAddr,
			Username:        cfg.Meshtastic.UpstreamForward.Username,
			Password:        cfg.Meshtastic.UpstreamForward.Password,
			TLS:             cfg.Meshtastic.UpstreamForward.TLS,
			ClientID:        cfg.Meshtastic.UpstreamForward.ClientID,
			Channels:        cfg.Meshtastic.UpstreamForward.Channels,
			BlockedChannels: cfg.Meshtastic.UpstreamForward.BlockedChannels,
		},
	}

	// Allow upstream broker password to be supplied via env var to avoid secrets in config.yaml.
	if pw := strings.TrimSpace(os.Getenv("UPSTREAM_MQTT_PASSWORD")); pw != "" {
		hookCfg.UpstreamForward.Password = pw
	}

	for _, c := range cfg.Meshtastic.Credentials {
		hookCfg.Credentials = append(hookCfg.Credentials, meshhook.Credential{
			Username:     c.Username,
			PasswordHash: c.PasswordHash,
		})
	}

	// Credentials can also be supplied via env vars BROKER_USERNAME / BROKER_PASSWORD_HASH,
	// which takes precedence and avoids putting secrets in config.yaml.
	if u, h := strings.TrimSpace(os.Getenv("BROKER_USERNAME")), strings.TrimSpace(os.Getenv("BROKER_PASSWORD_HASH")); u != "" && h != "" {
		hookCfg.Credentials = append(hookCfg.Credentials, meshhook.Credential{
			Username:     u,
			PasswordHash: h,
		})
	}

	for _, ch := range cfg.Meshtastic.Channels {
		psk, err := base64.StdEncoding.DecodeString(ch.PSKB64)
		if err != nil {
			log.Error("invalid PSK base64 for channel", "channel", ch.Name, "error", err)
			os.Exit(1)
		}
		hookCfg.Channels = append(hookCfg.Channels, meshhook.ChannelConfig{
			Name: ch.Name,
			PSK:  psk,
		})
	}

	hook := &meshhook.Hook{}
	if err := server.AddHook(hook, &hookCfg); err != nil {
		log.Error("failed to add meshtastic hook", "error", err)
		os.Exit(1)
	}

	// Optional HTTP stats endpoint.
	if cfg.StatsAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(hook.Stats().Snapshot())
		})
		statsSrv := &http.Server{
			Addr:         cfg.StatsAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		go func() {
			log.Info("stats endpoint listening", "addr", cfg.StatsAddr)
			if err := statsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("stats server error", "error", err)
			}
		}()
	}

	// Plain TCP listener.
	if cfg.TCPAddr != "" {
		if err := server.AddListener(listeners.NewTCP(listeners.Config{
			ID:      "tcp",
			Address: cfg.TCPAddr,
		})); err != nil {
			log.Error("failed to add TCP listener", "address", cfg.TCPAddr, "error", err)
			os.Exit(1)
		}
	}

	// TLS listener.
	if cfg.TLSAddr != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			log.Error("tls_addr set but cert_file/key_file not configured")
			os.Exit(1)
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Error("failed to load TLS certificate", "error", err)
			os.Exit(1)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if err := server.AddListener(listeners.NewTCP(listeners.Config{
			ID:        "tls",
			Address:   cfg.TLSAddr,
			TLSConfig: tlsCfg,
		})); err != nil {
			log.Error("failed to add TLS listener", "address", cfg.TLSAddr, "error", err)
			os.Exit(1)
		}
	}

	// WebSocket listener.
	if cfg.WSAddr != "" {
		if err := server.AddListener(listeners.NewWebsocket(listeners.Config{
			ID:      "ws",
			Address: cfg.WSAddr,
		})); err != nil {
			log.Error("failed to add WebSocket listener", "address", cfg.WSAddr, "error", err)
			os.Exit(1)
		}
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		log.Info("shutting down")
		if err := server.Close(); err != nil {
			log.Error("error during shutdown", "error", err)
		}
	}()

	if err := server.Serve(); err != nil {
		log.Error("server error", "error", err)
		os.Exit(1)
	}

	// Block until Close() signals the done channel.
	select {}
}

// loadConfig reads and parses the YAML config file. If the file does not exist
// a default config is returned so the server can start with sane defaults.
func loadConfig(path string, log *slog.Logger) (serverConfig, error) {
	cfg := serverConfig{
		TCPAddr: ":1883",
		Meshtastic: meshtasticConfig{
			RateLimits: meshhook.RateLimitConfig{
				PacketsPerWindow: 100,
				WindowSecs:       60,
				DedupWindowSecs:  60,
			},
		},
	}

	data, err := os.ReadFile(path) // #nosec G304 — path is a user-supplied CLI flag
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("config file not found, using defaults", "path", path)
			return cfg, nil
		}
		return cfg, err
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}
