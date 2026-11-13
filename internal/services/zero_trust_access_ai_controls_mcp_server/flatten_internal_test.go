package zero_trust_access_ai_controls_mcp_server

import (
	"encoding/json"
	"testing"
)

func TestNormalizeServerReadEmptyLists(t *testing.T) {
	field := func(body []byte, k string) string {
		var env struct {
			Result map[string]json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return string(env.Result[k])
	}

	t.Run("absent lists injected as empty", func(t *testing.T) {
		out := normalizeServerRead([]byte(`{"result":{"id":"s","name":"x"}}`))
		for _, k := range []string{"updated_prompts", "updated_tools"} {
			if got := field(out, k); got != "[]" {
				t.Errorf("%s = %q, want []", k, got)
			}
		}
	})

	t.Run("null list coerced to empty", func(t *testing.T) {
		out := normalizeServerRead([]byte(`{"result":{"id":"s","updated_prompts":null,"updated_tools":null}}`))
		for _, k := range []string{"updated_prompts", "updated_tools"} {
			if got := field(out, k); got != "[]" {
				t.Errorf("%s = %q, want []", k, got)
			}
		}
	})

	t.Run("present list preserved untouched, absent sibling emptied", func(t *testing.T) {
		tools := `[{"name":"verify_token"},{"name":"get_zone","enabled":true}]`
		out := normalizeServerRead([]byte(`{"result":{"id":"s","updated_tools":` + tools + `}}`))
		if got := field(out, "updated_tools"); got != tools {
			t.Errorf("updated_tools mutated: got %s want %s", got, tools)
		}
		if got := field(out, "updated_prompts"); got != "[]" {
			t.Errorf("updated_prompts = %q, want []", got)
		}
	})

	t.Run("both lists present -> body unchanged", func(t *testing.T) {
		in := []byte(`{"result":{"id":"s","updated_prompts":[{"name":"p"}],"updated_tools":[{"name":"t"}]}}`)
		if string(normalizeServerRead(in)) != string(in) {
			t.Errorf("expected unchanged body")
		}
	})

	t.Run("no result key -> unchanged", func(t *testing.T) {
		in := []byte(`{"errors":[]}`)
		if string(normalizeServerRead(in)) != string(in) {
			t.Errorf("expected unchanged body")
		}
	})

	t.Run("unparseable -> unchanged", func(t *testing.T) {
		in := []byte(`not json`)
		if string(normalizeServerRead(in)) != string(in) {
			t.Errorf("expected unchanged body")
		}
	})
}

func TestPreserveEmptyOverrides(t *testing.T) {
	empty := []*ZeroTrustAccessAIControlsMcpServerUpdatedToolsModel{}
	decoded := &ZeroTrustAccessAIControlsMcpServerModel{UpdatedTools: &empty}
	preserveEmptyOverrides(decoded, &ZeroTrustAccessAIControlsMcpServerModel{})
	if decoded.UpdatedTools != nil {
		t.Errorf("updated_tools = %v, want nil (prior form)", decoded.UpdatedTools)
	}

	full := []*ZeroTrustAccessAIControlsMcpServerUpdatedToolsModel{{}}
	decoded = &ZeroTrustAccessAIControlsMcpServerModel{UpdatedTools: &full}
	preserveEmptyOverrides(decoded, &ZeroTrustAccessAIControlsMcpServerModel{})
	if decoded.UpdatedTools == nil || len(*decoded.UpdatedTools) != 1 {
		t.Errorf("non-empty updated_tools must be kept")
	}
}
