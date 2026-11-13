package zero_trust_device_custom_profile_test

import (
	"context"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/services/zero_trust_device_custom_profile"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

type (
	profileModel     = zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileModel
	serviceModeModel = zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileServiceModeV2Model
)

func dcpSchema() rschema.Schema {
	return zero_trust_device_custom_profile.ResourceSchema(context.TODO())
}

func updateState() tfsdk.State {
	ot := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	return tfsdk.State{Raw: tftypes.NewValue(ot, map[string]tftypes.Value{})}
}

func createState() tfsdk.State {
	ot := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	return tfsdk.State{Raw: tftypes.NewValue(ot, nil)}
}

// Server-managed computed attributes reuse prior state (null included) on update
// and stay unknown on create.
func TestDeviceCustomProfileStatePreservingModifiers(t *testing.T) {
	t.Parallel()
	s := dcpSchema()

	{
		m := s.Attributes["default"].(rschema.BoolAttribute).PlanModifiers
		if got := applyBoolMods(m, updateState(), types.BoolNull(), types.BoolUnknown(), types.BoolNull()); !got.IsNull() {
			t.Fatalf("default update(null state): expected null preserved, got %#v", got)
		}
		if got := applyBoolMods(m, updateState(), types.BoolValue(false), types.BoolUnknown(), types.BoolNull()); !got.Equal(types.BoolValue(false)) {
			t.Fatalf("default update(value): expected reuse, got %#v", got)
		}
		if got := applyBoolMods(m, createState(), types.BoolNull(), types.BoolUnknown(), types.BoolNull()); !got.IsUnknown() {
			t.Fatalf("default create: expected unknown, got %#v", got)
		}
	}

	{
		m := s.Attributes["gateway_unique_id"].(rschema.StringAttribute).PlanModifiers
		if got := applyStringMods(m, updateState(), types.StringValue("gw"), types.StringUnknown(), types.StringNull()); !got.Equal(types.StringValue("gw")) {
			t.Fatalf("gateway_unique_id update: expected reuse, got %#v", got)
		}
		if got := applyStringMods(m, createState(), types.StringNull(), types.StringUnknown(), types.StringNull()); !got.IsUnknown() {
			t.Fatalf("gateway_unique_id create: expected unknown, got %#v", got)
		}
	}

	{
		a := s.Attributes["service_mode_v2"].(rschema.SingleNestedAttribute)
		at := objAttrTypes(a)
		if got := applyObjectMods(a.PlanModifiers, updateState(), types.ObjectNull(at), types.ObjectUnknown(at), types.ObjectNull(at)); !got.IsNull() {
			t.Fatalf("service_mode_v2 update(null state): expected null preserved, got %#v", got)
		}
		if got := applyObjectMods(a.PlanModifiers, createState(), types.ObjectNull(at), types.ObjectUnknown(at), types.ObjectNull(at)); !got.IsUnknown() {
			t.Fatalf("service_mode_v2 create: expected unknown, got %#v", got)
		}
	}

	// exclude and dns_search_suffixes carry schema modifiers; include and
	// target_tests are preserved by ModifyPlan (see TestDeviceCustomProfileModifyPlan).
	for _, name := range []string{"exclude", "dns_search_suffixes"} {
		a := s.Attributes[name].(rschema.ListNestedAttribute)
		et := listElemType(a)
		known := types.ListValueMust(et, []attr.Value{})
		if got := applyListMods(a.PlanModifiers, updateState(), known, types.ListUnknown(et), types.ListNull(et)); !got.Equal(known) {
			t.Fatalf("%s update([]): expected reuse, got %#v", name, got)
		}
		if got := applyListMods(a.PlanModifiers, createState(), types.ListNull(et), types.ListUnknown(et), types.ListNull(et)); !got.IsUnknown() {
			t.Fatalf("%s create: expected unknown, got %#v", name, got)
		}
	}
}

// switch_locked is user-driven and must not be silently pinned to prior state.
func TestDeviceCustomProfileUserFieldNotStatePreserved(t *testing.T) {
	t.Parallel()
	a := dcpSchema().Attributes["switch_locked"].(rschema.BoolAttribute)
	if got := applyBoolMods(a.PlanModifiers, updateState(), types.BoolValue(true), types.BoolUnknown(), types.BoolNull()); !got.IsUnknown() {
		t.Fatalf("switch_locked must not reuse prior state, got %#v", got)
	}
}

func TestDeviceCustomProfileModifyPlan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := func(mode string, port types.Float64) customfield.NestedObject[serviceModeModel] {
		return customfield.NewObjectMust(ctx, &serviceModeModel{Mode: types.StringValue(mode), Port: port})
	}
	unknownPort := types.Float64Unknown()

	for _, tt := range []struct {
		name                string
		create              bool
		prior, plan, config customfield.NestedObject[serviceModeModel]
		wantPort            types.Float64
	}{
		{name: "unchanged proxy mode keeps port", prior: svc("proxy", types.Float64Value(3128)), plan: svc("proxy", unknownPort), config: svc("proxy", types.Float64Null()), wantPort: types.Float64Value(3128)},
		{name: "unchanged warp mode keeps null port", prior: svc("warp", types.Float64Null()), plan: svc("warp", unknownPort), config: svc("warp", types.Float64Null()), wantPort: types.Float64Null()},
		{name: "mode change leaves port unknown", prior: svc("proxy", types.Float64Value(3128)), plan: svc("warp", unknownPort), config: svc("warp", types.Float64Null()), wantPort: unknownPort},
		{name: "configured port wins", prior: svc("proxy", types.Float64Value(3128)), plan: svc("proxy", types.Float64Value(8080)), config: svc("proxy", types.Float64Value(8080)), wantPort: types.Float64Value(8080)},
		{name: "unknown configured port stays unknown", prior: svc("proxy", types.Float64Value(3128)), plan: svc("proxy", unknownPort), config: svc("proxy", unknownPort), wantPort: unknownPort},
		{name: "create leaves port unknown", create: true, plan: svc("proxy", unknownPort), config: svc("proxy", types.Float64Null()), wantPort: unknownPort},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := dcpSchema()
			base := profileModel{
				ID: types.StringValue("p1"), PolicyID: types.StringValue("p1"), AccountID: types.StringValue("acc"),
				Name: types.StringValue("n"), ProfileType: types.StringValue("warp"),
				DNSSearchSuffixes: customfield.NullObjectList[zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileDNSSearchSuffixesModel](ctx),
				Exclude:           customfield.NullObjectList[zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileExcludeModel](ctx),
				Include:           customfield.NullObjectList[zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileIncludeModel](ctx),
				FallbackDomains:   customfield.NullObjectList[zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileFallbackDomainsModel](ctx),
				TargetTests:       customfield.NullObjectList[zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileTargetTestsModel](ctx),
			}

			state := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
			if !tt.create {
				prior := base
				prior.ServiceModeV2 = tt.prior
				if d := state.Set(ctx, &prior); d.HasError() {
					t.Fatalf("set state: %v", d)
				}
			}

			planned := base
			planned.ServiceModeV2 = tt.plan
			planned.Include = customfield.UnknownObjectList[zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileIncludeModel](ctx)
			planned.TargetTests = customfield.UnknownObjectList[zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileTargetTestsModel](ctx)
			plan := tfsdk.Plan{Schema: s}
			if d := plan.Set(ctx, &planned); d.HasError() {
				t.Fatalf("set plan: %v", d)
			}

			configured := base
			configured.ServiceModeV2 = tt.config
			cfg := tfsdk.State{Schema: s}
			if d := cfg.Set(ctx, &configured); d.HasError() {
				t.Fatalf("set config: %v", d)
			}

			resp := resource.ModifyPlanResponse{Plan: plan}
			zero_trust_device_custom_profile.NewResource().(*zero_trust_device_custom_profile.ZeroTrustDeviceCustomProfileResource).ModifyPlan(ctx, resource.ModifyPlanRequest{
				Plan: plan, State: state, Config: tfsdk.Config{Schema: s, Raw: cfg.Raw},
			}, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("modify plan: %v", resp.Diagnostics)
			}

			var got profileModel
			if d := resp.Plan.Get(ctx, &got); d.HasError() {
				t.Fatalf("get plan: %v", d)
			}
			smv2, d := got.ServiceModeV2.Value(ctx)
			if d.HasError() || smv2 == nil {
				t.Fatalf("service_mode_v2 missing: %v", d)
			}
			if !smv2.Port.Equal(tt.wantPort) {
				t.Errorf("service_mode_v2.port = %s, want %s", smv2.Port, tt.wantPort)
			}
			if !tt.create && (!got.Include.IsNull() || !got.TargetTests.IsNull()) {
				t.Errorf("null include/target_tests not preserved on update: include=%s target_tests=%s", got.Include, got.TargetTests)
			}
		})
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

func applyBoolMods(mods []planmodifier.Bool, st tfsdk.State, state, plan, config types.Bool) types.Bool {
	ctx := context.TODO()
	cur := plan
	for _, m := range mods {
		resp := &planmodifier.BoolResponse{PlanValue: cur}
		m.PlanModifyBool(ctx, planmodifier.BoolRequest{State: st, StateValue: state, PlanValue: cur, ConfigValue: config}, resp)
		cur = resp.PlanValue
	}
	return cur
}

func applyObjectMods(mods []planmodifier.Object, st tfsdk.State, state, plan, config types.Object) types.Object {
	ctx := context.TODO()
	cur := plan
	for _, m := range mods {
		resp := &planmodifier.ObjectResponse{PlanValue: cur}
		m.PlanModifyObject(ctx, planmodifier.ObjectRequest{State: st, StateValue: state, PlanValue: cur, ConfigValue: config}, resp)
		cur = resp.PlanValue
	}
	return cur
}

func applyListMods(mods []planmodifier.List, st tfsdk.State, state, plan, config types.List) types.List {
	ctx := context.TODO()
	cur := plan
	for _, m := range mods {
		resp := &planmodifier.ListResponse{PlanValue: cur}
		m.PlanModifyList(ctx, planmodifier.ListRequest{State: st, StateValue: state, PlanValue: cur, ConfigValue: config}, resp)
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

func listElemType(a rschema.ListNestedAttribute) attr.Type {
	m := map[string]attr.Type{}
	for k, sub := range a.NestedObject.Attributes {
		m[k] = sub.GetType()
	}
	return types.ObjectType{AttrTypes: m}
}
