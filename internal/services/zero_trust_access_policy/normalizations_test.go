package zero_trust_access_policy

import (
	"context"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/apijson"
	"github.com/stretchr/testify/require"
)

func requireSameRules(t *testing.T, expected, actual ZeroTrustAccessPolicyModel) {
	t.Helper()
	require.True(t, expected.Include.Equal(actual.Include), "include: expected %s, got %s", expected.Include, actual.Include)
	require.True(t, expected.Exclude.Equal(actual.Exclude), "exclude: expected %s, got %s", expected.Exclude, actual.Exclude)
	require.True(t, expected.Require.Equal(actual.Require), "require: expected %s, got %s", expected.Require, actual.Require)
}

// A real selector stamps an empty copy of itself onto sibling rules; the
// phantom must go while the real selector and the siblings survive.
func TestPruneEmptySelectorsStampedOntoSiblings(t *testing.T) {
	tests := []struct {
		name     string
		phantoms string
		clean    string
	}{
		{
			name: "gsuite",
			phantoms: `[{"gsuite":{"email":"admin@example.org","identity_provider_id":"idp-id"}},` +
				`{"email_domain":{"domain":"example.com"},"gsuite":{"email":null,"identity_provider_id":null}},` +
				`{"email":{"email":"user@example.com"},"gsuite":{"email":null,"identity_provider_id":null}}]`,
			clean: `[{"gsuite":{"email":"admin@example.org","identity_provider_id":"idp-id"}},` +
				`{"email_domain":{"domain":"example.com"}},` +
				`{"email":{"email":"user@example.com"}}]`,
		},
		{
			name: "group, saml and service_token_tag",
			phantoms: `[{"group":{"id":"group-id"},"saml":{"attribute_name":null,"attribute_value":null,"identity_provider_id":null}},` +
				`{"saml":{"attribute_name":"role","attribute_value":"admin","identity_provider_id":"idp-id"},"service_token_tag":{"key":null,"value":null}},` +
				`{"service_token_tag":{"key":"env","value":"prod"},"group":{"id":null}}]`,
			clean: `[{"group":{"id":"group-id"}},` +
				`{"saml":{"attribute_name":"role","attribute_value":"admin","identity_provider_id":"idp-id"}},` +
				`{"service_token_tag":{"key":"env","value":"prod"}}]`,
		},
		{
			name: "id and url selectors",
			phantoms: `[{"email_list":{"id":"list-id"},"ip_list":{"id":null},"login_method":{"id":null}},` +
				`{"external_evaluation":{"evaluate_url":"https://e.example.com","keys_url":"https://k.example.com"},"azureAD":{"id":null,"identity_provider_id":null}},` +
				`{"user_risk_score":{"user_risk_score":["high"]},"okta":{"identity_provider_id":null,"name":null},"github-organization":{"identity_provider_id":null,"name":null}}]`,
			clean: `[{"email_list":{"id":"list-id"}},` +
				`{"external_evaluation":{"evaluate_url":"https://e.example.com","keys_url":"https://k.example.com"}},` +
				`{"user_risk_score":{"user_risk_score":["high"]}}]`,
		},
	}
	for _, field := range []string{"include", "exclude", "require"} {
		for _, tt := range tests {
			t.Run(field+"/"+tt.name, func(t *testing.T) {
				ctx := context.Background()
				var data, expected ZeroTrustAccessPolicyModel
				require.NoError(t, apijson.Unmarshal([]byte(`{"`+field+`":`+tt.phantoms+`}`), &data))
				require.NoError(t, apijson.Unmarshal([]byte(`{"`+field+`":`+tt.clean+`}`), &expected))
				diags := pruneEmptyConditionSelectors(ctx, &data)
				require.False(t, diags.HasError(), "%v", diags)
				requireSameRules(t, expected, data)
			})
		}
	}
}

// Content-less selectors are legitimately empty objects and must not be pruned.
func TestPruneEmptySelectorsPreservesContentlessSelectors(t *testing.T) {
	rules := `[{"everyone":{}},{"certificate":{}},{"any_valid_service_token":{}},{"cloudflare_account_member":{}}]`
	for _, field := range []string{"include", "exclude", "require"} {
		t.Run(field, func(t *testing.T) {
			ctx := context.Background()
			var data, expected ZeroTrustAccessPolicyModel
			require.NoError(t, apijson.Unmarshal([]byte(`{"`+field+`":`+rules+`}`), &data))
			require.NoError(t, apijson.Unmarshal([]byte(`{"`+field+`":`+rules+`}`), &expected))
			diags := pruneEmptyConditionSelectors(ctx, &data)
			require.False(t, diags.HasError(), "%v", diags)
			requireSameRules(t, expected, data)
		})
	}
}

func TestImportNormalizationPrunesEmptySelectors(t *testing.T) {
	phantoms := `[{"gsuite":{"email":"admin@example.org","identity_provider_id":"idp-id"}},` +
		`{"email":{"email":"user@example.com"},"gsuite":{"email":null,"identity_provider_id":null}}]`
	clean := `[{"gsuite":{"email":"admin@example.org","identity_provider_id":"idp-id"}},` +
		`{"email":{"email":"user@example.com"}}]`
	for _, field := range []string{"include", "exclude", "require"} {
		t.Run(field, func(t *testing.T) {
			ctx := context.Background()
			var data, expected ZeroTrustAccessPolicyModel
			require.NoError(t, apijson.Unmarshal([]byte(`{"`+field+`":`+phantoms+`}`), &data))
			require.NoError(t, apijson.Unmarshal([]byte(`{"`+field+`":`+clean+`}`), &expected))
			diags := normalizeImportZeroTrustAccessPolicyAPIData(ctx, &data)
			require.False(t, diags.HasError(), "%v", diags)
			switch field {
			case "include":
				require.True(t, expected.Include.Equal(data.Include), "expected %s, got %s", expected.Include, data.Include)
			case "exclude":
				require.True(t, expected.Exclude.Equal(data.Exclude), "expected %s, got %s", expected.Exclude, data.Exclude)
			default:
				require.True(t, expected.Require.Equal(data.Require), "expected %s, got %s", expected.Require, data.Require)
			}
		})
	}
}
