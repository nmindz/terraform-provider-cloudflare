// Package v501 strips the page and per_page list query parameters that leaked
// into turnstile_widget resource state (schema versions 1 and 500).
package v501

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

func UpgradeFromV500(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	if req.RawState == nil {
		return
	}

	var rawAttrs map[string]json.RawMessage
	if err := json.Unmarshal(req.RawState.JSON, &rawAttrs); err != nil {
		resp.Diagnostics.AddError("failed to parse state during turnstile_widget v501 migration", err.Error())
		return
	}

	delete(rawAttrs, "page")
	delete(rawAttrs, "per_page")

	cleaned, err := json.Marshal(rawAttrs)
	if err != nil {
		resp.Diagnostics.AddError("failed to serialise state during turnstile_widget v501 migration", err.Error())
		return
	}

	targetType := resp.State.Schema.Type().TerraformType(ctx)
	tfVal, err := (&tfprotov6.RawState{JSON: cleaned}).Unmarshal(targetType)
	if err != nil {
		resp.Diagnostics.AddError("failed to unmarshal cleaned state during turnstile_widget v501 migration", err.Error())
		return
	}

	resp.State.Raw = tfVal
}
