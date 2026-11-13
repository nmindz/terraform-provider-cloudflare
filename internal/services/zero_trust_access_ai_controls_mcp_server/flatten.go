package zero_trust_access_ai_controls_mcp_server

import (
	"encoding/json"
)

// normalizeServerRead injects [] for an absent/null updated_prompts/updated_tools
// so an unset override matches config's [] instead of re-planning every run.
// Lists the API returns are untouched. Returns the input unchanged on parse error.
func normalizeServerRead(body []byte) []byte {
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) != nil {
		return body
	}
	var server map[string]json.RawMessage
	if resRaw, ok := env["result"]; !ok || json.Unmarshal(resRaw, &server) != nil || server == nil {
		return body
	}

	changed := false
	for _, k := range []string{"updated_prompts", "updated_tools"} {
		if v, has := server[k]; !has || string(v) == "null" {
			server[k] = json.RawMessage("[]")
			changed = true
		}
	}
	if !changed {
		return body
	}

	ns, err := json.Marshal(server)
	if err != nil {
		return body
	}
	env["result"] = ns
	out, err := json.Marshal(env)
	if err != nil {
		return body
	}
	return out
}

// preserveEmptyOverrides keeps the prior (plan or state) null-vs-[] form of an
// empty updated_prompts/updated_tools, so both `[]` and omitted config converge.
func preserveEmptyOverrides(decoded *ZeroTrustAccessAIControlsMcpServerModel, prior *ZeroTrustAccessAIControlsMcpServerModel) {
	if prior == nil {
		return
	}
	decoded.UpdatedPrompts = keepPriorEmptyForm(decoded.UpdatedPrompts, prior.UpdatedPrompts)
	decoded.UpdatedTools = keepPriorEmptyForm(decoded.UpdatedTools, prior.UpdatedTools)
}

func keepPriorEmptyForm[T any](cur, prior *[]*T) *[]*T {
	if isEmptyList(cur) && isEmptyList(prior) {
		return prior
	}
	return cur
}

func isEmptyList[T any](l *[]*T) bool {
	return l == nil || len(*l) == 0
}
