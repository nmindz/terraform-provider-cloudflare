package v501_test

import (
	"context"
	_ "embed"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/services/turnstile_widget"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/services/turnstile_widget/migration/v501"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

//go:embed testdata/v500_state.json
var v500State []byte

func TestUpgradeFromV500_StripsPageAndPerPage(t *testing.T) {
	ctx := context.Background()
	schema := turnstile_widget.ResourceSchema(ctx)

	req := resource.UpgradeStateRequest{RawState: &tfprotov6.RawState{JSON: v500State}}
	resp := resource.UpgradeStateResponse{
		State: tfsdk.State{
			Schema: schema,
			Raw:    tftypes.NewValue(schema.Type().TerraformType(ctx), nil),
		},
	}

	v501.UpgradeFromV500(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	var name types.String
	resp.Diagnostics.Append(resp.State.GetAttribute(ctx, path.Root("name"), &name)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("read name: %v", resp.Diagnostics)
	}
	if name.ValueString() != "example" {
		t.Errorf("name = %q, want example", name.ValueString())
	}

	objType, ok := schema.Type().TerraformType(ctx).(tftypes.Object)
	if !ok {
		t.Fatal("schema type is not an object")
	}
	for _, k := range []string{"page", "per_page"} {
		if _, ok := objType.AttributeTypes[k]; ok {
			t.Errorf("schema still declares %q", k)
		}
	}
}

func TestUpgradeFromV500_NilRawState(t *testing.T) {
	ctx := context.Background()
	resp := resource.UpgradeStateResponse{}
	v501.UpgradeFromV500(ctx, resource.UpgradeStateRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
}
