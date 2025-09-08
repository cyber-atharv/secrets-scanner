/*
©cyber-atharv | 2026
builtin_test.go

Tests for rules/builtin.go

Tests:
  RegisterBuiltins loads at least 70 rules
  All rules have non-empty ID, description, keywords, and a non-nil pattern with no duplicates
  Pattern match correctness for 50+ services (AWS, GitHub, GitLab, GCP, Azure, Stripe,
    Twilio, Slack, JWT, SSH/PGP keys, DB connection strings, Shopify, npm, PyPI, Docker,
    Vault, DigitalOcean, Grafana, Databricks, HuggingFace, Supabase, and more)
  MatchKeywords routes content to the correct rule by keyword
  No false positives on benign code patterns (imports, constants, comments, loops)
*/

package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterBuiltins(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	RegisterBuiltins(reg)
	assert.GreaterOrEqual(t, reg.Len(), 70)
}

func TestBuiltinRuleIDs(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	RegisterBuiltins(reg)
	seen := make(map[string]bool)
	for _, r := range reg.All() {
		assert.NotEmpty(t, r.ID)
		assert.NotEmpty(t, r.Description)
		assert.NotEmpty(t, r.Keywords)
		assert.NotNil(t, r.Pattern)
		assert.False(t, seen[r.ID], "duplicate ID: %s", r.ID)
		seen[r.ID] = true
	}
}

func TestBuiltinPatternMatches(t *testing.T) { //nolint:funlen,gocognit
	t.Parallel()

	tests := map[string]struct {
		ruleID    string
		input     string
		wantMatch bool
		wantGroup string
	}{
		"aws access key": { //nolint:gosec
			ruleID:    "aws-access-key-id",
			input:     `aws_key = "AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00"`,
			wantMatch: true,
			wantGroup: "AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00",
		},
		"aws access key ABIA prefix": {
			ruleID:    "aws-access-key-id",
			input:     `ABIAIOSFODNN7EXAMPL0`,
			wantMatch: true,
			wantGroup: "ABIAIOSFODNN7EXAMPL0",
		},
		"aws access key too short": {
			ruleID:    "aws-access-key-id",
			input:     `AKIA1234`,
			wantMatch: false,
		},
		"github pat classic": {
			ruleID:    "github-pat-classic",
			input:     `ghp_DUMMY_TEST_GITHUB_TOKEN_000000000000`,
			wantMatch: true,
			wantGroup: "ghp_DUMMY_TEST_GITHUB_TOKEN_000000000000",
		},
		"github pat fine-grained": {
			ruleID:    "github-pat-fine",
			input:     `github_pat_abcdefghijABCDEFGHIJKL_abcdefghij0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABC`,
			wantMatch: true,
		},
		"github oauth": {
			ruleID:    "github-oauth-token",
			input:     `gho_DUMMY_TOKEN`,
			wantMatch: true,
			wantGroup: "gho_DUMMY_TOKEN",
		},
		"github app token": {
			ruleID:    "github-app-token",
			input:     `ghs_DUMMY_TOKEN`,
			wantMatch: true,
			wantGroup: "ghs_DUMMY_TOKEN",
		},
		"github refresh token": {
			ruleID:    "github-refresh-token",
			input:     `ghr_DUMMY_TOKEN`,
			wantMatch: true,
			wantGroup: "ghr_DUMMY_TOKEN",
		},
		"gitlab pat": {
			ruleID:    "gitlab-pat",
			input:     `glpat-DUMMY_TOKEN_TEST_12`,
			wantMatch: true,
			wantGroup: "glpat-DUMMY_TOKEN_TEST_12",
		},
		"gitlab pipeline trigger": {
			ruleID:    "gitlab-pipeline-trigger",
			input:     `glptt-abcdefghijklmnopqrstuvwxyz0123456789ABCD`,
			wantMatch: true,
			wantGroup: "glptt-abcdefghijklmnopqrstuvwxyz0123456789ABCD",
		},
		"gitlab runner token": {
			ruleID:    "gitlab-runner-token",
			input:     `glrt-xYz1234567890AbCdEfGh`,
			wantMatch: true,
			wantGroup: "glrt-xYz1234567890AbCdEfGh",
		},
		"gcp api key": {
			ruleID:    "gcp-api-key",
			input:     `AIzaSyDabcdefghij1234567890KLMNOPQRSTUV`,
			wantMatch: true,
		},
		"gcp service account": {
			ruleID:    "gcp-service-account",
			input:     `"type" : "service_account"`,
			wantMatch: true,
		},
		"gcp oauth secret": {
			ruleID:    "gcp-oauth-client-secret",
			input:     `GOCSPX-aBcDeFgHiJkLmNoPqRsTuVwXyZ01`,
			wantMatch: true,
		},
		"azure storage key": {
			ruleID: "azure-storage-key",
			input: `AccountKey=` +
				`abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`,
			wantMatch: true,
		},
		"slack bot token": {
			ruleID:    "slack-bot-token",
			input:     `xoxb-dummy-test-slack-token`,
			wantMatch: true,
		},
		"slack webhook": { //nolint:gosec
			ruleID:    "slack-webhook",
			input:     `https://hooks.slack.com/services/DUMMY/TEST/TOKEN`,
			wantMatch: true,
		},
		"stripe live key": { //nolint:gosec
			ruleID:    "stripe-live-secret",
			input:     `sk_test_DUMMY_STRIPE_KEY_00000000`,
			wantMatch: true,
			wantGroup: "sk_test_DUMMY_STRIPE_KEY_00000000",
		},
		"stripe test key": {
			ruleID:    "stripe-test-secret",
			input:     `sk_test_DUMMY_TOKEN_FOR_TESTS_1234`, //nolint:gosec
			wantMatch: true,
			wantGroup: "sk_test_DUMMY_TOKEN_FOR_TESTS_1234", //nolint:gosec
		},
		"stripe restricted live": { //nolint:gosec
			ruleID:    "stripe-live-restricted",
			input:     `rk_test_dummy_token_for_tests`,
			wantMatch: true,
			wantGroup: "rk_test_dummy_token_for_tests",
		},
		"stripe webhook secret": {
			ruleID:    "stripe-webhook-secret",
			input:     `whsec_MfKBGsXP8r7B2cGnQ9jT6KxL12AbCdEf`,
			wantMatch: true,
		},
		"twilio api key": {
			ruleID:    "twilio-api-key",
			input:     `SK_DUMMY_TWILIO_KEY_FOR_TESTS_00000`,
			wantMatch: true,
			wantGroup: "SK_DUMMY_TWILIO_KEY_FOR_TESTS_00000",
		},
		"twilio account sid": {
			ruleID:    "twilio-account-sid",
			input:     `AC_DUMMY_TWILIO_ACCOUNT_SID_00000`,
			wantMatch: true,
			wantGroup: "AC_DUMMY_TWILIO_ACCOUNT_SID_00000",
		},
		"sendgrid api key": {
			ruleID:    "sendgrid-api-key",
			input:     `SG.DUMMY_KEY_FOR_UNIT_TESTING_PURPOSES`,
			wantMatch: true,
		},
		"shopify access token": {
			ruleID:    "shopify-access-token",
			input:     `shpat_DUMMY_TEST_TOKEN_HEX_STRING_0`,
			wantMatch: true,
			wantGroup: "shpat_DUMMY_TEST_TOKEN_HEX_STRING_0",
		},
		"shopify custom app": {
			ruleID:    "shopify-custom-app",
			input:     `shpca_DUMMY_TEST_TOKEN_HEX_STRING_0`,
			wantMatch: true,
			wantGroup: "shpca_DUMMY_TEST_TOKEN_HEX_STRING_0",
		},
		"shopify private app": {
			ruleID:    "shopify-private-app",
			input:     `shppa_DUMMY_TEST_TOKEN_HEX_STRING_0`,
			wantMatch: true,
			wantGroup: "shppa_DUMMY_TEST_TOKEN_HEX_STRING_0",
		},
		"shopify shared secret": {
			ruleID:    "shopify-shared-secret",
			input:     `shpss_DUMMY_SECRET_TEST_TOKEN_HEX`,
			wantMatch: true,
			wantGroup: "shpss_DUMMY_SECRET_TEST_TOKEN_HEX",
		},
		"npm access token": {
			ruleID:    "npm-access-token",
			input:     `npm_DUMMY_TOKEN_FOR_TESTS_123456789`,
			wantMatch: true,
		},
		"pypi token": {
			ruleID: "pypi-api-token",
			input: `pypi-AgEIcHlwaS5vcmc_DUMMY_TEST_TOKEN` +
				`jIxLTk2OWU4YmViZDM3NgACKlszLCJjODA0ZWE1OC1kMjFiLTQzMjMtYWR` +
				`mNy0xZjQ4MGQ`,
			wantMatch: true,
		},
		"rubygems api key": {
			ruleID:    "rubygems-api-key",
			input:     `rubygems_DUMMY_SECRET_TEST_TOKENabcdef0123456789`,
			wantMatch: true,
		},
		"docker hub pat": {
			ruleID:    "docker-hub-pat",
			input:     `dckr_pat_aBcDeFgHiJkLmNoPqRsTuVwXyZ01`,
			wantMatch: true,
		},
		"jwt": {
			ruleID: "jwt-token",
			input: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.` +
				`eyJzdWIiOiIxMjM0NTY3ODkwIn0.` +
				`dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
			wantMatch: true,
		},
		"rsa private key": { //nolint:gosec
			ruleID:    "ssh-private-key-rsa",
			input:     `-----BEGIN RSA PRIVATE KEY-----`,
			wantMatch: true,
		},
		"openssh private key": {
			ruleID:    "ssh-private-key-openssh",
			input:     `-----BEGIN OPENSSH PRIVATE KEY-----`, //nolint:gosec
			wantMatch: true,
		},
		"ec private key": { //nolint:gosec
			ruleID:    "ssh-private-key-ec",
			input:     `-----BEGIN EC PRIVATE KEY-----`,
			wantMatch: true,
		},
		"dsa private key": { //nolint:gosec
			ruleID:    "ssh-private-key-dsa",
			input:     `-----BEGIN DSA PRIVATE KEY-----`,
			wantMatch: true,
		},
		"pgp private key": { //nolint:gosec
			ruleID:    "pgp-private-key",
			input:     `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			wantMatch: true,
		},
		"pkcs8 private key": {
			ruleID:    "private-key-pkcs8",
			input:     `-----BEGIN PRIVATE KEY-----`,
			wantMatch: true,
		},
		"generic password": {
			ruleID:    "generic-password",
			input:     `password = "my$ecretP@ss99"`,
			wantMatch: true,
			wantGroup: "my$ecretP@ss99",
		},
		"generic password no match on short": {
			ruleID:    "generic-password",
			input:     `password = "abc"`,
			wantMatch: false,
		},
		"generic secret": {
			ruleID:    "generic-secret",
			input:     `secret_key = "xK9mP2vL5nQ8jR3tB7"`,
			wantMatch: true,
			wantGroup: "xK9mP2vL5nQ8jR3tB7",
		},
		"generic api key": {
			ruleID:    "generic-api-key",
			input:     `api_key = "aK9mP2vL5nQ8jR3tB7wX4cD"`,
			wantMatch: true,
			wantGroup: "aK9mP2vL5nQ8jR3tB7wX4cD",
		},
		"generic token": {
			ruleID:    "generic-token",
			input:     `access_token = "xK9mP2vL5nQ8jR3tB7wY"`,
			wantMatch: true,
			wantGroup: "xK9mP2vL5nQ8jR3tB7wY",
		},
		"postgres connection": { //nolint:gosec
			ruleID:    "postgres-connection",
			input:     `postgresql://admin:s3cr3t@db.example.com:5432/mydb`,
			wantMatch: true,
		},
		"mysql connection": { //nolint:gosec
			ruleID:    "mysql-connection",
			input:     `mysql://root:password123@127.0.0.1:3306/app`,
			wantMatch: true,
		},
		"mongodb connection": { //nolint:gosec
			ruleID:    "mongodb-connection",
			input:     `mongodb+srv://user:p4ssw0rd@cluster0.abc.mongodb.net/db`,
			wantMatch: true,
		},
		"redis connection": { //nolint:gosec
			ruleID:    "redis-connection",
			input:     `redis://default:s3cret@redis.example.com:6379/0`,
			wantMatch: true,
		},
		"hashicorp vault token": {
			ruleID:    "hashicorp-vault-token",
			input:     `hvs.CAESIGH3YzJfaBcDeFgHiJkLmNoPqR`,
			wantMatch: true,
		},
		"digitalocean pat": {
			ruleID:    "digitalocean-pat",
			input:     `dop_v1_DUMMY_SECRET_TEST_TOKEN`,
			wantMatch: true,
			wantGroup: "dop_v1_DUMMY_SECRET_TEST_TOKEN",
		},
		"linear api key": {
			ruleID:    "linear-api-key",
			input:     `lin_api_DUMMY_SECRET_TEST_TOKEN`,
			wantMatch: true,
		},
		"age secret key": {
			ruleID:    "age-secret-key",
			input:     `AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ`,
			wantMatch: true,
		},
		"doppler token": {
			ruleID:    "doppler-token",
			input:     `dp.st.DUMMY_TOKEN_FOR_TESTS`,
			wantMatch: true,
		},
		"grafana sa token": {
			ruleID:    "grafana-api-key",
			input:     `glsa_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeF_12345678`,
			wantMatch: true,
		},
		"grafana cloud token": {
			ruleID:    "grafana-cloud-token",
			input:     `glc_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeF1`,
			wantMatch: true,
		},
		"databricks token": {
			ruleID:    "databricks-token",
			input:     `dapi_DUMMY_TOKEN_FOR_TESTS_12345`,
			wantMatch: true,
			wantGroup: "dapi_DUMMY_TOKEN_FOR_TESTS_12345",
		},
		"huggingface token": {
			ruleID:    "huggingface-token",
			input:     `hf_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJ`,
			wantMatch: true,
			wantGroup: "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJ",
		},
		"netlify token": {
			ruleID:    "netlify-token",
			input:     `nfp_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN`,
			wantMatch: true,
		},
		"postman api key": {
			ruleID:    "postman-api-key",
			input:     `PMAK-DUMMY-TOKEN-FOR-TESTS-12345ab`,
			wantMatch: true,
		},
		"figma pat": {
			ruleID:    "figma-pat",
			input:     `figd_DUMMY_TOKEN_FOR_TESTS_12345`,
			wantMatch: true,
		},
		"flyio token": {
			ruleID:    "flyio-token",
			input:     `fo1_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmN`,
			wantMatch: true,
		},
		"planetscale token": {
			ruleID:    "planetscale-token",
			input:     `pscale_tkn_DUMMY_TOKEN_FOR_TESTS`,
			wantMatch: true,
		},
		"replicate token": {
			ruleID:    "replicate-api-token",
			input:     `r8_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqR`,
			wantMatch: true,
		},
		"sentry auth token": {
			ruleID:    "sentry-auth-token",
			input:     `sntrys_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHi`,
			wantMatch: true,
		},
		"atlassian token": {
			ruleID:    "atlassian-api-token",
			input:     `ATATTaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwX`,
			wantMatch: true,
		},
		"render api key": {
			ruleID:    "render-api-key",
			input:     `rnd_aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHi`,
			wantMatch: true,
		},
		"launchdarkly sdk key": {
			ruleID:    "launchdarkly-sdk-key",
			input: `sdk-dummy-test-key-not-a-uuid`,
			wantMatch: true,
			wantGroup: "sdk-dummy-test-key-not-a-uuid",
		},
		"launchdarkly api key": {
			ruleID:    "launchdarkly-api-key",
			input: `api-dummy-test-key-not-a-uuid`,
			wantMatch: true,
			wantGroup: "api-dummy-test-key-not-a-uuid",
		},
		"okta api token": {
			ruleID:    "okta-api-token",
			input:     `OKTA_API_TOKEN = "00_DUMMY_OKTA_API_TOKEN_FOR_TESTS_ONLY"`,
			wantMatch: true,
			wantGroup: "00_DUMMY_OKTA_API_TOKEN_FOR_TESTS_ONLY",
		},
		"okta ssws header": {
			ruleID:    "okta-api-token",
			input:     `SSWS = "00_DUMMY_OKTA_SSWS_TOKEN_FOR_TESTS_ONLY"`,
			wantMatch: true,
			wantGroup: "00_DUMMY_OKTA_SSWS_TOKEN_FOR_TESTS_ONLY",
		},
		"supabase service key": {
			ruleID:    "supabase-service-key",
			input:     `SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.xxxxxxxx`,
			wantMatch: true,
			wantGroup: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.xxxxxxxx",
		},
		"supabase service key quoted": {
			ruleID:    "supabase-service-key",
			input:     `SUPABASE_SERVICE_ROLE_KEY="eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig123"`,
			wantMatch: true,
		},
		"no match on normal text": {
			ruleID:    "aws-access-key-id",
			input:     `this is just normal code`,
			wantMatch: false,
		},
	}

	reg := NewRegistry()
	RegisterBuiltins(reg)

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rule, ok := reg.Get(tc.ruleID)
			require.True(t, ok, "rule %s not found", tc.ruleID)

			match := rule.Pattern.FindStringSubmatch(tc.input)
			if tc.wantMatch {
				require.NotNil(t, match,
					"expected pattern match for rule %s", tc.ruleID)
				if tc.wantGroup != "" && rule.SecretGroup > 0 {
					require.Greater(t, len(match), rule.SecretGroup)
					assert.Equal(t, tc.wantGroup,
						match[rule.SecretGroup])
				}
			} else {
				assert.Nil(t, match,
					"unexpected match for rule %s", tc.ruleID)
			}
		})
	}
}

func TestBuiltinKeywordMatches(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	RegisterBuiltins(reg)

	tests := map[string]struct {
		content string
		wantIDs []string
	}{
		"aws content": { //nolint:gosec
			content: "found AKIA_DUMMY_TEST_KEY_FOR_SCANNER_00 in config",
			wantIDs: []string{"aws-access-key-id"},
		},
		"github content": {
			content: "token = ghp_abc123",
			wantIDs: []string{"github-pat-classic"},
		},
		"stripe content": {
			content: "key = sk_live_abc123",
			wantIDs: []string{"stripe-live-secret"},
		},
		"private key content": { //nolint:gosec
			content: "-----BEGIN RSA PRIVATE KEY-----",
			wantIDs: []string{"ssh-private-key-rsa"},
		},
		"postgres content": { //nolint:gosec
			content: "DATABASE_URL=postgres://user:pass@host/db",
			wantIDs: []string{"postgres-connection"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			matched := reg.MatchKeywords(tc.content)
			ids := make([]string, len(matched))
			for i, r := range matched {
				ids[i] = r.ID
			}
			for _, wantID := range tc.wantIDs {
				assert.Contains(t, ids, wantID)
			}
		})
	}
}

func TestBuiltinNoFalsePositives(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	RegisterBuiltins(reg)

	benignInputs := []string{
		`import os`,
		`func main() {}`,
		`const x = 42`,
		`// this is a comment`,
		`print("hello world")`,
		`if err != nil { return err }`,
		`for i := 0; i < 10; i++ {}`,
	}

	for _, rule := range reg.All() {
		for _, input := range benignInputs {
			match := rule.Pattern.FindString(input)
			assert.Empty(t, match,
				"rule %s false positive on: %s", rule.ID, input)
		}
	}
}
