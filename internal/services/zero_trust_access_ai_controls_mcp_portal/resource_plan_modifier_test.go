package zero_trust_access_ai_controls_mcp_portal_test

import (
	"context"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/services/zero_trust_access_ai_controls_mcp_portal"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func portalSchema() rschema.Schema {
	return zero_trust_access_ai_controls_mcp_portal.ResourceSchema(context.TODO())
}

func updateState() tfsdk.State {
	ot := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	return tfsdk.State{Raw: tftypes.NewValue(ot, map[string]tftypes.Value{})}
}

func createState() tfsdk.State {
	ot := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	return tfsdk.State{Raw: tftypes.NewValue(ot, nil)}
}

// created_* are immutable: reuse prior state on update, unknown on create.
func TestMcpPortalMetadataStatePreserved(t *testing.T) {
	t.Parallel()
	s := portalSchema()

	for _, name := range []string{"created_at", "created_by"} {
		a, ok := s.Attributes[name].(rschema.StringAttribute)
		if !ok {
			t.Fatalf("%s: expected StringAttribute", name)
		}
		m := a.PlanModifiers
		if len(m) == 0 {
			t.Fatalf("%s: missing plan modifier", name)
		}
		if got := applyStringMods(m, updateState(), types.StringValue("2026-05-04T19:34:26Z"), types.StringUnknown(), types.StringNull()); !got.Equal(types.StringValue("2026-05-04T19:34:26Z")) {
			t.Fatalf("%s no-op update: expected prior-state reuse, got %#v", name, got)
		}
		if got := applyStringMods(m, createState(), types.StringNull(), types.StringUnknown(), types.StringNull()); !got.IsUnknown() {
			t.Fatalf("%s create: expected unknown, got %#v", name, got)
		}
	}
}

// modified_* are re-stamped by the server on every write; pinning them causes
// "inconsistent result after apply".
func TestMcpPortalModifiedMetadataNotPinned(t *testing.T) {
	t.Parallel()
	s := portalSchema()

	for _, name := range []string{"modified_at", "modified_by"} {
		a, ok := s.Attributes[name].(rschema.StringAttribute)
		if !ok {
			t.Fatalf("%s: expected StringAttribute", name)
		}
		if len(a.PlanModifiers) != 0 {
			t.Fatalf("%s: expected NO plan modifier, got %d", name, len(a.PlanModifiers))
		}
	}
}

func applyStringMods(mods []planmodifier.String, st tfsdk.State, state, plan, config types.String) types.String {
	ctx := context.TODO()
	cur := plan
	for _, m := range mods {
		resp := &planmodifier.StringResponse{PlanValue: cur}
		m.PlanModifyString(ctx, planmodifier.StringRequest{State: st, StateValue: state, PlanValue: cur, ConfigValue: config}, resp)
		cur = resp.PlanValue
	}
	return cur
}
