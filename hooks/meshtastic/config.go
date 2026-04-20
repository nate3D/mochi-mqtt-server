package meshtastic

// Credential is a username + bcrypt-hashed password pair.
// Generate a hash with: htpasswd -bnBC 12 "" yourpassword | tr -d ':\n'
// or: go run golang.org/x/crypto/bcrypt -cost 12 yourpassword
type Credential struct {
	Username     string `yaml:"username" json:"username"`
	PasswordHash string `yaml:"password_hash" json:"password_hash"` // bcrypt hash
}

// ChannelConfig holds the configuration for a single Meshtastic channel,
// including the channel name and its pre-shared key (PSK).
type ChannelConfig struct {
	// Name is the channel name as it appears in the MQTT topic path (case-sensitive).
	Name string `yaml:"name" json:"name"`
	// PSK is the raw pre-shared key bytes for this channel.
	// For the default Meshtastic channels, use the single byte [0x01]
	// which will be automatically expanded to the well-known default key.
	// For custom channels, provide the full 16 or 32-byte key.
	PSK []byte `yaml:"psk" json:"psk"`
}

// RateLimitConfig controls per-node rate limiting and deduplication behaviour.
type RateLimitConfig struct {
	// PacketsPerWindow is the maximum number of packets a single node (From field)
	// may publish within WindowSecs. Zero disables rate limiting.
	PacketsPerWindow int `yaml:"packets_per_window" json:"packets_per_window"`
	// WindowSecs is the sliding window duration in seconds used for rate limiting.
	WindowSecs int `yaml:"window_secs" json:"window_secs"`
	// DedupWindowSecs is how long (in seconds) a seen (From, PacketID) pair is
	// cached to drop duplicate publishes from multiple gateway nodes.
	// Zero disables deduplication.
	DedupWindowSecs int `yaml:"dedup_window_secs" json:"dedup_window_secs"`
}

// UpstreamForwardConfig controls optional forwarding of validated Meshtastic
// packets to an upstream MQTT broker (e.g. the public mqtt.meshtastic.org server).
type UpstreamForwardConfig struct {
	// Enabled activates upstream forwarding. Default: false.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// BrokerAddr is the upstream broker host:port.
	// Defaults to "mqtt.meshtastic.org:1883" when empty.
	BrokerAddr string `yaml:"broker_addr" json:"broker_addr"`
	// Username for the upstream broker (leave empty for anonymous).
	Username string `yaml:"username" json:"username"`
	// Password for the upstream broker.
	Password string `yaml:"password" json:"password"`
	// TLS enables a TLS connection to the upstream broker (uses port 8883 by convention).
	TLS bool `yaml:"tls" json:"tls"`
	// ClientID is the MQTT client ID used when connecting upstream.
	// Defaults to "mochi-meshtastic-<hostname>" when empty.
	ClientID string `yaml:"client_id" json:"client_id"`
	// Channels is an optional allowlist of channel names to forward.
	// When empty, all channels that pass the local filters are forwarded.
	Channels []string `yaml:"channels" json:"channels"`
	// BlockedChannels is a denylist of channel names that will never be forwarded
	// to the upstream broker. Takes precedence over the Channels allowlist.
	// Packets on blocked channels are still processed locally (dedup, rate limit,
	// portnum filtering, subscribers on this broker) — they are only suppressed
	// from upstream forwarding.
	BlockedChannels []string `yaml:"blocked_channels" json:"blocked_channels"`
}

// Config is the configuration for the MeshtasticHook.
type Config struct {
	// Credentials is the list of allowed username/bcrypt-password pairs.
	// If empty, all connections are accepted without authentication.
	// Strongly recommended to set at least one credential on public brokers.
	Credentials []Credential `yaml:"credentials" json:"credentials"`

	// Channels lists channels the broker knows about. If a channel's PSK is
	// configured here the hook can decrypt and validate packet content.
	// Packets on unlisted channels are allowed through without decryption checks.
	Channels []ChannelConfig `yaml:"channels" json:"channels"`

	// BlockedPortNums is a list of Meshtastic portnums that will be silently
	// dropped. Takes precedence over AllowedPortNums.
	BlockedPortNums []int32 `yaml:"blocked_port_nums" json:"blocked_port_nums"`

	// AllowedPortNums, when non-empty, is an allowlist: only packets carrying
	// one of these portnums will be forwarded. Ignored when empty (allow all).
	AllowedPortNums []int32 `yaml:"allowed_port_nums" json:"allowed_port_nums"`

	// RateLimits controls per-node rate limiting and deduplication.
	RateLimits RateLimitConfig `yaml:"rate_limits" json:"rate_limits"`

	// RequireDecryptable, when true, drops any packet on a known channel that
	// cannot be decrypted with the configured PSK. Packets on channels not
	// listed in Channels are always forwarded regardless of this setting.
	RequireDecryptable bool `yaml:"require_decryptable" json:"require_decryptable"`

	// AllowJSON, when true, permits clients to publish to the JSON topic path
	// (msh/+/2/json/#). By default JSON paths are receive-only.
	AllowJSON bool `yaml:"allow_json" json:"allow_json"`

	// AllowedRegions restricts publishing to the listed region codes (e.g. "US",
	// "EU_868"). An empty slice allows all regions.
	AllowedRegions []string `yaml:"allowed_regions" json:"allowed_regions"`

	// UpstreamForward, when enabled, forwards validated packets to an upstream MQTT broker.
	UpstreamForward UpstreamForwardConfig `yaml:"upstream_forward" json:"upstream_forward"`
}
