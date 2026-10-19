package response

import (
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// RedactedValue is the placeholder that replaces any masked sensitive value.
const RedactedValue = "***REDACTED***"

// maskRule describes how a single type of sensitive data is detected and masked.
// Rules run against the serialized JSON response, so patterns must tolerate JSON string
// escaping (newlines appear as a literal \n and quotes as \").
type maskRule struct {
	// name is the PII type detected by this rule.
	name string
	// pattern matches the sensitive data.
	pattern *regexp.Regexp
	// replacement is the regexp expansion template used to build the masked output.
	replacement string
}

// maskRules are applied in order. Large PEM blocks go first so later rules don't partially rewrite them.
var maskRules = []maskRule{
	{
		name:        "tls_private_key",
		pattern:     regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
		replacement: RedactedValue,
	},
	{
		name:        "tls_certificate",
		pattern:     regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`),
		replacement: RedactedValue,
	},
	{
		name:        "docker_config_json",
		pattern:     regexp.MustCompile(`(\.dockerconfigjson\\?"?\s*:\s*\\?")[^"\\]+`),
		replacement: "${1}" + RedactedValue,
	},
	{
		// auth blocks inside a decoded docker config
		name:        "docker_config_json",
		pattern:     regexp.MustCompile(`(?i)(\\?"(?:auth|password|identitytoken|registrytoken)\\?"\s*:\s*\\?")[^"\\]+`),
		replacement: "${1}" + RedactedValue,
	},
	{
		name:        "kubeconfig_credential",
		pattern:     regexp.MustCompile(`(\b(?:client-certificate-data|client-key-data|token)\\?"?\s*:\s*\\?"?)[^"\\\s,}]+`),
		replacement: "${1}" + RedactedValue,
	},
	{
		name:        "bearer_token",
		pattern:     regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9\-._~+/]{12,}=*`),
		replacement: "${1}" + RedactedValue,
	},
	{
		// JWTs, which is the format of service account tokens
		name:        "bearer_token",
		pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`),
		replacement: RedactedValue,
	},
	{
		name:        "connection_string",
		pattern:     regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/\s"\\@]+:)[^@\s"\\/]+(@)`),
		replacement: "${1}" + RedactedValue + "${2}",
	},
}

var (
	// secretKindPattern detects a Secret manifest embedded in text, either as YAML or as escaped JSON.
	secretKindPattern = regexp.MustCompile(`kind\\?"?\s*:\s*\\?"?Secret\b`)
	// secretDataBlockPattern matches a data/stringData key followed by its indented entries in YAML text.
	secretDataBlockPattern = regexp.MustCompile(`(^|\\n|\s)(stringData|data):((?:(?:\\n|\n)[ \t]+[^\\\n:]+:[^\\\n]*)+)`)
	// secretDataEntryPattern matches a single "key: value" line inside a data block.
	secretDataEntryPattern = regexp.MustCompile(`([^\\\n:]+:)[^\\\n]*`)
)

// MaskSensitive redacts sensitive information (secret data, tokens, private keys, certificates,
// kubeconfig credentials, registry auth and credentials embedded in connection strings) from s.
func MaskSensitive(s string) string {
	if secretKindPattern.MatchString(s) {
		s = secretDataBlockPattern.ReplaceAllStringFunc(s, maskSecretDataBlock)
	}

	for _, rule := range maskRules {
		s = rule.pattern.ReplaceAllString(s, rule.replacement)
	}

	return s
}

// maskSecretDataBlock redacts the values of every entry in a matched data/stringData block, keeping the keys.
func maskSecretDataBlock(block string) string {
	m := secretDataBlockPattern.FindStringSubmatch(block)
	if m == nil {
		return block
	}

	entries := secretDataEntryPattern.ReplaceAllString(m[3], "${1} "+RedactedValue)
	return m[1] + m[2] + ":" + entries
}

// maskSecretObject redacts the values under data and stringData of a Secret, keeping the keys
// so it is still visible which entries exist. Objects of any other kind are left untouched.
func maskSecretObject(obj *unstructured.Unstructured) {
	if !strings.EqualFold(obj.GetKind(), "Secret") {
		return
	}

	for _, field := range []string{"data", "stringData"} {
		entries, found, err := unstructured.NestedMap(obj.Object, field)
		if err != nil || !found {
			continue
		}

		for k := range entries {
			entries[k] = RedactedValue
		}
		_ = unstructured.SetNestedMap(obj.Object, entries, field)
	}
}
