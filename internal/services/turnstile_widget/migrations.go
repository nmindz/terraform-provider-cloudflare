// File generated from our OpenAPI spec by Stainless. See CONTRIBUTING.md for details.

package turnstile_widget

import (
	"context"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/services/turnstile_widget/migration/v500"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/services/turnstile_widget/migration/v501"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ resource.ResourceWithUpgradeState = (*TurnstileWidgetResource)(nil)

// UpgradeState registers state upgraders for schema version changes.
//
//   - 0 (v4) → 501: full transformation (domains Set → sorted List, sitekey
//     copied from ID, new computed fields null).
//   - 1 (dormant v5) → 501: strip page/per_page.
//   - 500 → 501: strip page/per_page, leaked from the list query params.
func (r *TurnstileWidgetResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	sourceSchema := v500.SourceCloudfareTurnstileWidgetSchema()

	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema:   &sourceSchema,
			StateUpgrader: v500.UpgradeFromV4,
		},
		// No PriorSchema: raw state still carries page/per_page.
		1: {
			StateUpgrader: v501.UpgradeFromV500,
		},
		500: {
			StateUpgrader: v501.UpgradeFromV500,
		},
	}
}
