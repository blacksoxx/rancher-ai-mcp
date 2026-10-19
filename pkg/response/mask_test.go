package response

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestMaskSensitive(t *testing.T) {
	tests := map[string]struct {
		input     string
		expected  string
		unchanged bool
	}{
		"private key": {
			input:    `{"k":"-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\ndef==\n-----END RSA PRIVATE KEY-----\n"}`,
			expected: `{"k":"` + RedactedValue + `\n"}`,
		},
		"certificate": {
			input:    `{"k":"-----BEGIN CERTIFICATE-----\nMIIDabc\n-----END CERTIFICATE-----"}`,
			expected: `{"k":"` + RedactedValue + `"}`,
		},
		"bearer token": {
			input:    `{"h":"Authorization: Bearer abc.DEF-123_x+/=="}`,
			expected: `{"h":"Authorization: Bearer ` + RedactedValue + `"}`,
		},
		"jwt": {
			input:    `{"t":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"}`,
			expected: `{"t":"` + RedactedValue + `"}`,
		},
		"kubeconfig yaml": {
			input:    `{"c":"users:\n- user:\n    client-certificate-data: LS0tabc\n    client-key-data: LS0tdef\n    token: s3cr3t\n"}`,
			expected: `{"c":"users:\n- user:\n    client-certificate-data: ` + RedactedValue + `\n    client-key-data: ` + RedactedValue + `\n    token: ` + RedactedValue + `\n"}`,
		},
		"kubeconfig json": {
			input:    `{"token":"s3cr3t"}`,
			expected: `{"token":"` + RedactedValue + `"}`,
		},
		"dockerconfigjson": {
			input:    `{".dockerconfigjson":"eyJhdXRocyI6e319"}`,
			expected: `{".dockerconfigjson":"` + RedactedValue + `"}`,
		},
		"docker auth block": {
			input:    `{"auths":{"r.io":{"username":"u","auth":"dTpw"}}}`,
			expected: `{"auths":{"r.io":{"username":"u","auth":"` + RedactedValue + `"}}}`,
		},
		"connection string": {
			input:    `{"u":"postgres://admin:hunter2@db:5432/app"}`,
			expected: `{"u":"postgres://admin:` + RedactedValue + `@db:5432/app"}`,
		},
		"secret manifest yaml": {
			input:    `{"m":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  password: cGFzcw==\n  user: YWRtaW4=\ntype: Opaque\n"}`,
			expected: `{"m":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  password: ` + RedactedValue + `\n  user: ` + RedactedValue + `\ntype: Opaque\n"}`,
		},
		"configmap data untouched": {
			input:     `{"m":"kind: ConfigMap\ndata:\n  key: value\n"}`,
			unchanged: true,
		},
		"url without credentials": {
			input:     `{"u":"https://example.com:8443/path"}`,
			unchanged: true,
		},
		"plain text": {
			input:     `{"msg":"the bearer of this message has no token"}`,
			unchanged: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := MaskSensitive(test.input)
			if test.unchanged {
				assert.Equal(t, test.input, got)
				return
			}
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestCreateMcpResponseMasksSecret(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": "s", "namespace": "default"},
		"data":       map[string]any{"password": "cGFzcw=="},
		"stringData": map[string]any{"user": "admin"},
	}}

	got, err := CreateMcpResponse([]*unstructured.Unstructured{obj}, "local")
	require.NoError(t, err)

	assert.NotContains(t, got, "cGFzcw==")
	assert.NotContains(t, got, "admin")
	assert.Contains(t, got, `"password":"`+RedactedValue+`"`)
	assert.Contains(t, got, `"user":"`+RedactedValue+`"`)
}

const (
	fakeKey        = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\nVTiO9Vq3d1VxQ4kqO5Gm0bYhV8Zq2iJQ0X0y\n-----END RSA PRIVATE KEY-----\n"
	fakeCert       = "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\nRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0\n-----END CERTIFICATE-----\n"
	fakeJWT        = "eyJhbGciOiJSUzI1NiIsImtpZCI6IngxeTJ6MyJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6YXBwIn0.kQ3vXJ7mP0wZy1b2cD4eF5gH6iJ7kL8mN9oP0qR1sT2"
	fakeKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://10.0.0.1:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
users:
- name: admin
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURkekND
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFB
    token: kubeconfig-user-abc123:xyz789secrettokenvalue
`
)

func TestCreateMcpResponseMasksRealResources(t *testing.T) {
	tests := map[string]struct {
		obj *unstructured.Unstructured
		// leaked values that must not appear in the response
		secrets []string
		// values that must remain visible
		visible []string
	}{
		"opaque secret": {
			obj: &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata": map[string]any{
					"name": "db-credentials", "namespace": "prod",
					"annotations": map[string]any{"kubectl.kubernetes.io/last-applied-configuration": "{...}"},
				},
				"type": "Opaque",
				"data": map[string]any{"username": "YWRtaW4=", "password": "czNjcjN0UGFzc3cwcmQh"},
			}},
			secrets: []string{"YWRtaW4=", "czNjcjN0UGFzc3cwcmQh"},
			visible: []string{"db-credentials", `"username"`, `"password"`, "Opaque"},
		},
		"tls secret": {
			obj: &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]any{"name": "ingress-tls", "namespace": "prod"},
				"type":       "kubernetes.io/tls",
				"data":       map[string]any{"tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", "tls.key": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ=="},
			}},
			secrets: []string{"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ=="},
			visible: []string{"ingress-tls", `"tls.crt"`, `"tls.key"`},
		},
		"registry pull secret": {
			obj: &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]any{"name": "regcred", "namespace": "prod"},
				"type":       "kubernetes.io/dockerconfigjson",
				"data":       map[string]any{".dockerconfigjson": "eyJhdXRocyI6eyJyZWdpc3RyeS5leGFtcGxlLmNvbSI6eyJhdXRoIjoiZFRwdyJ9fX0="},
			}},
			secrets: []string{"eyJhdXRocyI6eyJyZWdpc3RyeS5leGFtcGxlLmNvbSI6eyJhdXRoIjoiZFRwdyJ9fX0="},
			visible: []string{"regcred", ".dockerconfigjson"},
		},
		"service account token secret with stringData kubeconfig": {
			obj: &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata": map[string]any{
					"name": "app-token", "namespace": "default",
					"annotations": map[string]any{"kubernetes.io/service-account.name": "app"},
				},
				"type":       "kubernetes.io/service-account-token",
				"data":       map[string]any{"token": fakeJWT, "ca.crt": fakeCert},
				"stringData": map[string]any{"kubeconfig": fakeKubeconfig},
			}},
			secrets: []string{fakeJWT, "MIIDdzCCAl", "xyz789secrettokenvalue", "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFB"},
			visible: []string{"app-token", "kubernetes.io/service-account.name"},
		},
		"configmap holding kubeconfig and connection string": {
			obj: &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata":   map[string]any{"name": "app-config", "namespace": "default"},
				"data": map[string]any{
					"kubeconfig":   fakeKubeconfig,
					"database.url": "postgres://app:Sup3rS3cret@postgres.default.svc:5432/app?sslmode=disable",
					"tls.pem":      fakeKey + fakeCert,
					"log.level":    "debug",
				},
			}},
			secrets: []string{"xyz789secrettokenvalue", "client-key-data: LS0t", "Sup3rS3cret", "MIIEowIBAAKCAQEA", "MIIDdzCCAl"},
			visible: []string{"app-config", "postgres.default.svc:5432/app", "debug", "https://10.0.0.1:6443"},
		},
		"deployment with credentials in env": {
			obj: &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]any{"name": "api", "namespace": "default"},
				"spec": map[string]any{
					"template": map[string]any{"spec": map[string]any{"containers": []any{
						map[string]any{
							"name":  "api",
							"image": "registry.example.com/api:1.2.3",
							"env": []any{
								map[string]any{"name": "DATABASE_URL", "value": "mysql://root:p4ssw0rd@mysql:3306/db"},
								map[string]any{"name": "AUTH_HEADER", "value": "Bearer " + fakeJWT},
								map[string]any{"name": "LOG_LEVEL", "value": "info"},
							},
						},
					}}},
				},
			}},
			secrets: []string{"p4ssw0rd", fakeJWT},
			visible: []string{"registry.example.com/api:1.2.3", "mysql://root:", "@mysql:3306/db", "LOG_LEVEL", "info"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := CreateMcpResponse([]*unstructured.Unstructured{test.obj}, "local")
			require.NoError(t, err)

			for _, s := range test.secrets {
				assert.NotContains(t, got, s)
			}
			for _, v := range test.visible {
				assert.Contains(t, got, v)
			}
			assert.Contains(t, got, RedactedValue)
		})
	}
}
