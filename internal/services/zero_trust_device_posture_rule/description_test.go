package zero_trust_device_posture_rule

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestNormalizeDescription(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		in   types.String
		want types.String
	}{
		{"null becomes empty", types.StringNull(), types.StringValue("")},
		{"empty stays empty", types.StringValue(""), types.StringValue("")},
		{"value kept", types.StringValue("desc"), types.StringValue("desc")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := &ZeroTrustDevicePostureRuleModel{Description: tt.in}
			normalizeDescription(data)
			if !data.Description.Equal(tt.want) {
				t.Fatalf("got %s, want %s", data.Description, tt.want)
			}
		})
	}
	normalizeDescription(nil)
}

func TestDescriptionPlanModifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := ResourceSchema(ctx).Attributes["description"].(schema.StringAttribute)
	obj := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	update := tfsdk.State{Raw: tftypes.NewValue(obj, map[string]tftypes.Value{})}
	create := tfsdk.State{Raw: tftypes.NewValue(obj, nil)}

	apply := func(st tfsdk.State, state, plan, config types.String) types.String {
		cur := plan
		for _, m := range a.PlanModifiers {
			resp := &planmodifier.StringResponse{PlanValue: cur}
			m.PlanModifyString(ctx, planmodifier.StringRequest{State: st, StateValue: state, PlanValue: cur, ConfigValue: config}, resp)
			cur = resp.PlanValue
		}
		return cur
	}

	if got := apply(update, types.StringValue(""), types.StringUnknown(), types.StringNull()); !got.Equal(types.StringValue("")) {
		t.Fatalf("update with unset description: expected prior \"\", got %s", got)
	}
	if got := apply(update, types.StringValue("old"), types.StringValue("new"), types.StringValue("new")); !got.Equal(types.StringValue("new")) {
		t.Fatalf("configured description must win, got %s", got)
	}
	if got := apply(create, types.StringNull(), types.StringUnknown(), types.StringNull()); !got.IsUnknown() {
		t.Fatalf("create: expected unknown, got %s", got)
	}
}
