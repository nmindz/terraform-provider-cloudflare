package zero_trust_access_ai_controls_mcp_portal

import (
	"context"
	"encoding/json"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

var serverOverrideKeys = []string{"updated_prompts", "updated_tools"}

// normalizePortalRead coerces a null/absent description to "" (the schema
// default) and injects [] for each server's absent updated_prompts/updated_tools,
// so unset values match config instead of churning the servers set. Lists the API
// returns are untouched. Returns the input unchanged on parse error.
func normalizePortalRead(body []byte) []byte {
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) != nil {
		return body
	}
	var portal map[string]json.RawMessage
	if resRaw, ok := env["result"]; !ok || json.Unmarshal(resRaw, &portal) != nil || portal == nil {
		return body
	}

	changed := false
	if d, has := portal["description"]; !has || string(d) == "null" {
		portal["description"] = json.RawMessage(`""`)
		changed = true
	}

	var servers []map[string]json.RawMessage
	if raw, ok := portal["servers"]; ok && json.Unmarshal(raw, &servers) == nil {
		serversChanged := false
		for _, s := range servers {
			for _, k := range serverOverrideKeys {
				if v, has := s[k]; !has || string(v) == "null" {
					s[k] = json.RawMessage("[]")
					serversChanged = true
				}
			}
		}
		if serversChanged {
			if ns, err := json.Marshal(servers); err == nil {
				portal["servers"] = ns
				changed = true
			}
		}
	}

	if !changed {
		return body
	}
	np, err := json.Marshal(portal)
	if err != nil {
		return body
	}
	env["result"] = np
	out, err := json.Marshal(env)
	if err != nil {
		return body
	}
	return out
}

// preserveEmptyServerOverrides keeps the prior (plan or state) null-vs-[] form
// of each server's empty updated_prompts/updated_tools, so both `[]` and omitted
// config converge; non-empty lists are never touched.
func preserveEmptyServerOverrides(
	ctx context.Context,
	decoded, prior customfield.NestedObjectSet[ZeroTrustAccessAIControlsMcpPortalServersModel],
) (customfield.NestedObjectSet[ZeroTrustAccessAIControlsMcpPortalServersModel], diag.Diagnostics) {
	if decoded.IsNullOrUnknown() || prior.IsNullOrUnknown() {
		return decoded, nil
	}
	servers, diags := decoded.AsStructSliceT(ctx)
	if diags.HasError() {
		return decoded, diags
	}
	priorServers, d := prior.AsStructSliceT(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return decoded, diags
	}

	byID := make(map[string]ZeroTrustAccessAIControlsMcpPortalServersModel, len(priorServers))
	for _, p := range priorServers {
		if !p.ServerID.IsNull() && !p.ServerID.IsUnknown() {
			byID[p.ServerID.ValueString()] = p
		}
	}

	changed := false
	for i := range servers {
		p, ok := byID[servers[i].ServerID.ValueString()]
		if !ok {
			continue
		}
		var c1, c2 bool
		servers[i].UpdatedPrompts, c1 = keepPriorEmptyForm(servers[i].UpdatedPrompts, p.UpdatedPrompts)
		servers[i].UpdatedTools, c2 = keepPriorEmptyForm(servers[i].UpdatedTools, p.UpdatedTools)
		changed = changed || c1 || c2
	}
	if !changed {
		return decoded, diags
	}

	out, d := customfield.NewObjectSet(ctx, servers)
	diags.Append(d...)
	if diags.HasError() {
		return decoded, diags
	}
	return out, diags
}

// keepPriorEmptyForm returns prior when both lists are empty but differ in
// null-vs-[] form, and cur otherwise.
func keepPriorEmptyForm[T any](cur, prior *[]*T) (*[]*T, bool) {
	if isEmptyList(cur) && isEmptyList(prior) && (cur == nil) != (prior == nil) {
		return prior, true
	}
	return cur, false
}

func isEmptyList[T any](l *[]*T) bool {
	return l == nil || len(*l) == 0
}
