// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package zero_trust_dlp_predefined_profile_test

import (
	"context"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/services/zero_trust_dlp_predefined_profile"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/test_helpers"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func TestZeroTrustDLPPredefinedProfileModelSchemaParity(t *testing.T) {
	t.Parallel()
	model := (*zero_trust_dlp_predefined_profile.ZeroTrustDLPPredefinedProfileModel)(nil)
	schema := zero_trust_dlp_predefined_profile.ResourceSchema(context.TODO())
	errs := test_helpers.ValidateResourceModelSchemaIntegrity(model, schema)
	errs.Report(t)
}

func TestZeroTrustDLPPredefinedProfileSchema_NoInjectedDefaults(t *testing.T) {
	t.Parallel()
	s := zero_trust_dlp_predefined_profile.ResourceSchema(context.TODO())

	ct, ok := s.Attributes["confidence_threshold"].(schema.StringAttribute)
	if !ok {
		t.Fatal("confidence_threshold is not a string attribute")
	}
	if ct.Default != nil {
		t.Error("confidence_threshold must not have a default")
	}
	if len(ct.PlanModifiers) == 0 {
		t.Error("confidence_threshold must carry state forward when unconfigured")
	}

	name, _ := s.Attributes["name"].(schema.StringAttribute)
	if len(name.PlanModifiers) == 0 {
		t.Error("name must carry state forward")
	}
	openAccess, _ := s.Attributes["open_access"].(schema.BoolAttribute)
	if len(openAccess.PlanModifiers) == 0 {
		t.Error("open_access must carry state forward")
	}
}
