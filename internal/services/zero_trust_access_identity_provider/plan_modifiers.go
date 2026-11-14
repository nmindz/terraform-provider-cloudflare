package zero_trust_access_identity_provider

import (
	"context"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func modifyPlan(ctx context.Context, req resource.ModifyPlanRequest, res *resource.ModifyPlanResponse) {
	var planApp, stateApp, configApp *ZeroTrustAccessIdentityProviderModel
	res.Diagnostics.Append(req.Plan.Get(ctx, &planApp)...)
	res.Diagnostics.Append(req.State.Get(ctx, &stateApp)...)
	res.Diagnostics.Append(req.Config.Get(ctx, &configApp)...)
	if res.Diagnostics.HasError() || planApp == nil {
		return
	}

	if stateApp != nil && knownObject(stateApp.SCIMConfig) && knownObject(planApp.SCIMConfig) {
		stateModel, _ := stateApp.SCIMConfig.Value(ctx)
		planModel, _ := planApp.SCIMConfig.Value(ctx)
		var configModel *ZeroTrustAccessIdentityProviderSCIMConfigModel
		if configApp != nil && knownObject(configApp.SCIMConfig) {
			configModel, _ = configApp.SCIMConfig.Value(ctx)
		}

		if stateModel != nil && planModel != nil {
			reconcileSCIMConfigPlan(planModel, configModel, stateModel)
			planApp.SCIMConfig, _ = customfield.NewObject(ctx, planModel)
		}
	}

	res.Plan.Set(ctx, &planApp)
}

func knownObject(v customfield.NestedObject[ZeroTrustAccessIdentityProviderSCIMConfigModel]) bool {
	return !v.IsNull() && !v.IsUnknown()
}

// reconcileSCIMConfigPlan carries server-computed scim_config values over from
// state so an unchanged provider plans no diff. config may be nil.
func reconcileSCIMConfigPlan(plan, config, state *ZeroTrustAccessIdentityProviderSCIMConfigModel) {
	// Enabling SCIM makes the API issue a new secret and base URL.
	enabling := (state.Enabled.IsNull() || !state.Enabled.ValueBool()) && plan.Enabled.ValueBool()

	if enabling {
		plan.Secret = types.StringUnknown()
		plan.SCIMBaseURL = types.StringUnknown()
	} else {
		plan.Secret = state.Secret
		// Null-preserving: the API omits it while SCIM is disabled.
		plan.SCIMBaseURL = state.SCIMBaseURL
	}

	// Unconfigured: keep whatever the API last returned (may be null).
	if config == nil || config.IdentityUpdateBehavior.IsNull() {
		plan.IdentityUpdateBehavior = state.IdentityUpdateBehavior
	}
}
