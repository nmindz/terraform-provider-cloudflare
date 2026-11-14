package zero_trust_access_identity_provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func scimModel(enabled bool, behavior, baseURL, secret types.String) *ZeroTrustAccessIdentityProviderSCIMConfigModel {
	return &ZeroTrustAccessIdentityProviderSCIMConfigModel{
		Enabled:                types.BoolValue(enabled),
		IdentityUpdateBehavior: behavior,
		SCIMBaseURL:            baseURL,
		SeatDeprovision:        types.BoolValue(false),
		Secret:                 secret,
		UserDeprovision:        types.BoolValue(false),
	}
}

func TestReconcileSCIMConfigPlan_NullCarriedFromState(t *testing.T) {
	t.Parallel()
	state := scimModel(false, types.StringNull(), types.StringNull(), types.StringNull())
	plan := scimModel(false, types.StringUnknown(), types.StringUnknown(), types.StringUnknown())
	config := scimModel(false, types.StringNull(), types.StringNull(), types.StringNull())

	reconcileSCIMConfigPlan(plan, config, state)

	if !plan.IdentityUpdateBehavior.IsNull() {
		t.Errorf("identity_update_behavior = %v, want null", plan.IdentityUpdateBehavior)
	}
	if !plan.SCIMBaseURL.IsNull() {
		t.Errorf("scim_base_url = %v, want null", plan.SCIMBaseURL)
	}
}

func TestReconcileSCIMConfigPlan_KnownCarriedFromState(t *testing.T) {
	t.Parallel()
	state := scimModel(true, types.StringValue("automatic"), types.StringValue("https://x/scim"), types.StringValue("s"))
	plan := scimModel(true, types.StringUnknown(), types.StringUnknown(), types.StringUnknown())

	reconcileSCIMConfigPlan(plan, nil, state)

	if plan.IdentityUpdateBehavior.ValueString() != "automatic" {
		t.Errorf("identity_update_behavior = %v, want automatic", plan.IdentityUpdateBehavior)
	}
	if plan.SCIMBaseURL.ValueString() != "https://x/scim" {
		t.Errorf("scim_base_url = %v, want state value", plan.SCIMBaseURL)
	}
	if plan.Secret.ValueString() != "s" {
		t.Errorf("secret = %v, want state value", plan.Secret)
	}
}

func TestReconcileSCIMConfigPlan_ConfiguredValueKept(t *testing.T) {
	t.Parallel()
	state := scimModel(false, types.StringNull(), types.StringNull(), types.StringNull())
	plan := scimModel(false, types.StringValue("reauth"), types.StringUnknown(), types.StringUnknown())
	config := scimModel(false, types.StringValue("reauth"), types.StringNull(), types.StringNull())

	reconcileSCIMConfigPlan(plan, config, state)

	if plan.IdentityUpdateBehavior.ValueString() != "reauth" {
		t.Errorf("identity_update_behavior = %v, want reauth", plan.IdentityUpdateBehavior)
	}
}

func TestReconcileSCIMConfigPlan_EnablingMakesComputedUnknown(t *testing.T) {
	t.Parallel()
	state := scimModel(false, types.StringNull(), types.StringNull(), types.StringNull())
	plan := scimModel(true, types.StringUnknown(), types.StringNull(), types.StringNull())
	config := scimModel(true, types.StringNull(), types.StringNull(), types.StringNull())

	reconcileSCIMConfigPlan(plan, config, state)

	if !plan.SCIMBaseURL.IsUnknown() {
		t.Errorf("scim_base_url = %v, want unknown when enabling", plan.SCIMBaseURL)
	}
	if !plan.Secret.IsUnknown() {
		t.Errorf("secret = %v, want unknown when enabling", plan.Secret)
	}
}
