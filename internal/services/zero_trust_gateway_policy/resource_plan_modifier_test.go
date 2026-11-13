package zero_trust_gateway_policy_test

import (
	"context"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/services/zero_trust_gateway_policy"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Stable server-managed attributes must reuse prior state (including null) on update instead of
// re-planning as "(known after apply)", and stay unknown on create.

func gwSchema() rschema.Schema {
	return zero_trust_gateway_policy.ResourceSchema(context.TODO())
}

// updateState has a non-null Raw, i.e. an in-place update.
func updateState() tfsdk.State {
	ot := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	return tfsdk.State{Raw: tftypes.NewValue(ot, map[string]tftypes.Value{})}
}

// createState has a null Raw, i.e. a create.
func createState() tfsdk.State {
	ot := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	return tfsdk.State{Raw: tftypes.NewValue(ot, nil)}
}

func TestGatewayPolicyStableComputedStringsHoldState(t *testing.T) {
	t.Parallel()
	s := gwSchema()

	for _, name := range []string{"created_at", "deleted_at", "source_account"} {
		a, ok := s.Attributes[name].(rschema.StringAttribute)
		if !ok {
			t.Fatalf("%s: expected StringAttribute", name)
		}
		m := a.PlanModifiers
		if got := applyStringMods(m, updateState(), types.StringNull(), types.StringUnknown(), types.StringNull()); !got.IsNull() {
			t.Fatalf("%s update(null state): expected null preserved, got %#v", name, got)
		}
		if got := applyStringMods(m, updateState(), types.StringValue("v"), types.StringUnknown(), types.StringNull()); !got.Equal(types.StringValue("v")) {
			t.Fatalf("%s update(value): expected reuse, got %#v", name, got)
		}
		if got := applyStringMods(m, createState(), types.StringNull(), types.StringUnknown(), types.StringNull()); !got.IsUnknown() {
			t.Fatalf("%s create: expected unknown, got %#v", name, got)
		}
	}
}

func TestGatewayPolicyStableComputedBoolsHoldState(t *testing.T) {
	t.Parallel()
	s := gwSchema()

	for _, name := range []string{"read_only", "sharable"} {
		a, ok := s.Attributes[name].(rschema.BoolAttribute)
		if !ok {
			t.Fatalf("%s: expected BoolAttribute", name)
		}
		m := a.PlanModifiers
		if got := applyBoolMods(m, updateState(), types.BoolNull(), types.BoolUnknown(), types.BoolNull()); !got.IsNull() {
			t.Fatalf("%s update(null state): expected null preserved, got %#v", name, got)
		}
		if got := applyBoolMods(m, updateState(), types.BoolValue(true), types.BoolUnknown(), types.BoolNull()); !got.Equal(types.BoolValue(true)) {
			t.Fatalf("%s update(value): expected reuse, got %#v", name, got)
		}
		if got := applyBoolMods(m, createState(), types.BoolNull(), types.BoolUnknown(), types.BoolNull()); !got.IsUnknown() {
			t.Fatalf("%s create: expected unknown, got %#v", name, got)
		}
	}
}

func TestGatewayPolicyComputedOptionalObjectsHoldState(t *testing.T) {
	t.Parallel()
	s := gwSchema()

	for _, name := range []string{"expiration", "schedule", "rule_settings"} {
		a, ok := s.Attributes[name].(rschema.SingleNestedAttribute)
		if !ok {
			t.Fatalf("%s: expected SingleNestedAttribute", name)
		}
		m := a.PlanModifiers
		at := objAttrTypes(a)
		if got := applyObjectMods(m, updateState(), types.ObjectNull(at), types.ObjectUnknown(at), types.ObjectNull(at)); !got.IsNull() {
			t.Fatalf("%s update(null state): expected null preserved, got %#v", name, got)
		}
		known := types.ObjectValueMust(at, nullVals(t, at))
		if got := applyObjectMods(m, updateState(), known, types.ObjectUnknown(at), types.ObjectNull(at)); !got.Equal(known) {
			t.Fatalf("%s update(value): expected reuse, got %#v", name, got)
		}
		if got := applyObjectMods(m, createState(), types.ObjectNull(at), types.ObjectUnknown(at), types.ObjectNull(at)); !got.IsUnknown() {
			t.Fatalf("%s create: expected unknown, got %#v", name, got)
		}
		// A configured value flows through untouched.
		if got := applyObjectMods(m, updateState(), types.ObjectNull(at), known, known); !got.Equal(known) {
			t.Fatalf("%s edit: expected configured value, got %#v", name, got)
		}
	}
}

// Attributes the server re-stamps on every update must stay unknown, or apply fails with
// "Provider produced inconsistent result".
func TestGatewayPolicyRestampedComputedStayUnknown(t *testing.T) {
	t.Parallel()
	s := gwSchema()

	for _, name := range []string{"updated_at", "warning_status"} {
		a := s.Attributes[name].(rschema.StringAttribute)
		if got := applyStringMods(a.PlanModifiers, updateState(), types.StringValue("v"), types.StringUnknown(), types.StringNull()); !got.IsUnknown() {
			t.Fatalf("%s must not reuse prior state, got %#v", name, got)
		}
	}
	v := s.Attributes["version"].(rschema.Int64Attribute)
	if len(v.PlanModifiers) != 0 {
		t.Fatalf("version must not carry plan modifiers, got %d", len(v.PlanModifiers))
	}
}

func TestGatewayPolicyUserFieldsNotStatePreserved(t *testing.T) {
	t.Parallel()
	s := gwSchema()

	for _, name := range []string{"action", "traffic"} {
		a := s.Attributes[name].(rschema.StringAttribute)
		if got := applyStringMods(a.PlanModifiers, updateState(), types.StringValue("x"), types.StringUnknown(), types.StringNull()); !got.IsUnknown() {
			t.Fatalf("%s must not reuse prior state, got %#v", name, got)
		}
	}
}

// API-populated rule_settings leaves are Computed so server values don't drift against an
// omitted config.
func TestGatewayPolicyRuleSettingsLeavesComputed(t *testing.T) {
	t.Parallel()
	rs := gwSchema().Attributes["rule_settings"].(rschema.SingleNestedAttribute)

	for _, name := range []string{
		"allow_child_bypass", "block_page_enabled", "block_reason",
		"insecure_disable_dnssec_validation", "ip_categories", "ip_indicator_feeds",
		"override_host", "override_ips", "resolve_dns_through_cloudflare",
	} {
		a := rs.Attributes[name]
		if !a.IsComputed() || !a.IsOptional() {
			t.Fatalf("rule_settings.%s: expected Computed+Optional", name)
		}
	}
}

func applyStringMods(mods []planmodifier.String, st tfsdk.State, state, plan, config types.String) types.String {
	cur := plan
	for _, m := range mods {
		resp := &planmodifier.StringResponse{PlanValue: cur}
		m.PlanModifyString(context.TODO(), planmodifier.StringRequest{State: st, StateValue: state, PlanValue: cur, ConfigValue: config}, resp)
		cur = resp.PlanValue
	}
	return cur
}

func applyBoolMods(mods []planmodifier.Bool, st tfsdk.State, state, plan, config types.Bool) types.Bool {
	cur := plan
	for _, m := range mods {
		resp := &planmodifier.BoolResponse{PlanValue: cur}
		m.PlanModifyBool(context.TODO(), planmodifier.BoolRequest{State: st, StateValue: state, PlanValue: cur, ConfigValue: config}, resp)
		cur = resp.PlanValue
	}
	return cur
}

func applyObjectMods(mods []planmodifier.Object, st tfsdk.State, state, plan, config types.Object) types.Object {
	cur := plan
	for _, m := range mods {
		resp := &planmodifier.ObjectResponse{PlanValue: cur}
		m.PlanModifyObject(context.TODO(), planmodifier.ObjectRequest{State: st, StateValue: state, PlanValue: cur, ConfigValue: config}, resp)
		cur = resp.PlanValue
	}
	return cur
}

func objAttrTypes(a rschema.SingleNestedAttribute) map[string]attr.Type {
	m := map[string]attr.Type{}
	for k, sub := range a.Attributes {
		m[k] = sub.GetType()
	}
	return m
}

func nullVals(t *testing.T, at map[string]attr.Type) map[string]attr.Value {
	ctx := context.TODO()
	out := map[string]attr.Value{}
	for k, ty := range at {
		v, err := ty.ValueFromTerraform(ctx, tftypes.NewValue(ty.TerraformType(ctx), nil))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		out[k] = v
	}
	return out
}
