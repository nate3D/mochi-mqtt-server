package meshtastic

import (
	"strings"

	generated "github.com/meshtastic/go/generated"
)

// ParsedTopic holds the validated, parsed parts of a Meshtastic MQTT topic.
type ParsedTopic struct {
	// Root is everything between "msh/" and "/2/" — may include a community
	// suffix, e.g. "US" or "US/memphismesh.com".
	Root    string
	Type    string // "e", "c", or "json"
	Channel string
	NodeID  string
}

// ParseTopic parses and validates a Meshtastic MQTT topic string.
// The Meshtastic root topic is configurable and may contain multiple segments,
// e.g. "msh/US/2/e/..." or "msh/US/memphismesh.com/2/e/...".
// We locate the "/2/" protocol version marker to handle both forms.
// Returns a non-empty reason string if the topic is not valid.
func ParseTopic(topic string) (ParsedTopic, string) {
	if !strings.HasPrefix(topic, "msh/") {
		return ParsedTopic{}, "topic does not begin with msh/"
	}

	// Strip the "msh/" prefix then find the "/2/" protocol version marker.
	rest := topic[len("msh/"):]

	const versionMarker = "/2/"
	vIdx := strings.Index(rest, versionMarker)
	if vIdx < 0 {
		return ParsedTopic{}, "missing /2/ protocol version marker in topic"
	}

	root := rest[:vIdx] // e.g. "US" or "US/memphismesh.com"
	if root == "" {
		return ParsedTopic{}, "topic root/region is empty"
	}

	// Everything after "/2/" is: TYPE[/CHANNEL/NODEID]
	after := rest[vIdx+len(versionMarker):]
	parts := strings.SplitN(after, "/", 3)

	ptype := parts[0]
	if ptype != "e" && ptype != "c" && ptype != "json" && ptype != "map" {
		return ParsedTopic{}, "unknown topic type, expected e, c, json, or map"
	}

	// map topics use msh/ROOT/2/map/ — no channel or node ID segment.
	if ptype == "map" {
		return ParsedTopic{Root: root, Type: ptype}, ""
	}

	if len(parts) < 3 {
		return ParsedTopic{}, "topic does not have enough segments after /2/"
	}

	channel := parts[1]
	if channel == "" {
		return ParsedTopic{}, "topic channel name is empty"
	}

	nodeID := parts[2]
	if !strings.HasPrefix(nodeID, "!") {
		return ParsedTopic{}, "topic node ID must begin with !"
	}

	return ParsedTopic{
		Root:    root,
		Type:    ptype,
		Channel: channel,
		NodeID:  nodeID,
	}, ""
}

// IsMeshtasticTopic returns true if the topic starts with the "msh/" prefix.
func IsMeshtasticTopic(topic string) bool {
	return strings.HasPrefix(topic, "msh/")
}

// IsJSONTopic returns true if the topic is a Meshtastic JSON path.
func IsJSONTopic(topic string) bool {
	_, reason := ParseTopic(topic)
	if reason != "" {
		return false
	}
	pt, _ := ParseTopic(topic)
	return pt.Type == "json"
}

// IsValidEnvelope performs structural validation of a parsed ServiceEnvelope.
// It checks that the required fields are present and that the packet is
// encrypted (Decoded must be nil — we never accept client-decrypted payloads).
func IsValidEnvelope(env *generated.ServiceEnvelope) bool {
	if env == nil {
		return false
	}

	if strings.TrimSpace(env.GetChannelId()) == "" {
		return false
	}

	if strings.TrimSpace(env.GetGatewayId()) == "" {
		return false
	}

	pk := env.GetPacket()
	if pk == nil {
		return false
	}

	if pk.GetId() == 0 {
		return false
	}

	if pk.GetFrom() == 0 {
		return false
	}

	// The Decoded field being non-nil means the client sent a pre-decrypted
	// packet. We only accept encrypted payloads.
	if pk.GetDecoded() != nil {
		return false
	}

	if len(pk.GetEncrypted()) == 0 {
		return false
	}

	return true
}
