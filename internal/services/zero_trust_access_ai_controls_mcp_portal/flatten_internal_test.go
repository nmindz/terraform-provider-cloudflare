package zero_trust_access_ai_controls_mcp_portal

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestNormalizePortalReadPassthrough(t *testing.T) {
	t.Run("nothing to normalize -> unchanged", func(t *testing.T) {
		in := []byte(`{"result":{"id":"p","name":"x","description":""}}`)
		if string(normalizePortalRead(in)) != string(in) {
			t.Errorf("expected unchanged body")
		}
	})
	t.Run("unparseable -> unchanged", func(t *testing.T) {
		in := []byte(`not json`)
		if string(normalizePortalRead(in)) != string(in) {
			t.Errorf("expected unchanged body on parse error")
		}
	})
}

func TestNormalizePortalServersReadEmptyLists(t *testing.T) {
	server := func(body []byte, idx int) map[string]json.RawMessage {
		var env struct {
			Result struct {
				Servers []map[string]json.RawMessage `json:"servers"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return env.Result.Servers[idx]
	}

	t.Run("absent lists injected as empty", func(t *testing.T) {
		in := []byte(`{"result":{"servers":[{"server_id":"a"}]}}`)
		s := server(normalizePortalRead(in), 0)
		for _, k := range serverOverrideKeys {
			if string(s[k]) != "[]" {
				t.Errorf("%s = %q, want []", k, string(s[k]))
			}
		}
	})

	t.Run("null lists coerced to empty", func(t *testing.T) {
		in := []byte(`{"result":{"servers":[{"server_id":"a","updated_prompts":null,"updated_tools":null}]}}`)
		s := server(normalizePortalRead(in), 0)
		for _, k := range serverOverrideKeys {
			if string(s[k]) != "[]" {
				t.Errorf("%s = %q, want []", k, string(s[k]))
			}
		}
	})

	t.Run("present list preserved untouched, absent sibling emptied", func(t *testing.T) {
		tools := `[{"name":"verify_token"},{"name":"get_zone","enabled":true}]`
		in := []byte(`{"result":{"servers":[{"server_id":"a","updated_tools":` + tools + `}]}}`)
		s := server(normalizePortalRead(in), 0)
		if string(s["updated_tools"]) != tools {
			t.Errorf("updated_tools mutated: got %s want %s", s["updated_tools"], tools)
		}
		if string(s["updated_prompts"]) != "[]" {
			t.Errorf("updated_prompts = %q, want []", string(s["updated_prompts"]))
		}
	})
}

func TestNormalizePortalReadDescription(t *testing.T) {
	desc := func(body []byte) string {
		var env struct {
			Result map[string]json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return string(env.Result["description"])
	}

	t.Run("null description -> empty string", func(t *testing.T) {
		if got := desc(normalizePortalRead([]byte(`{"result":{"id":"p","description":null}}`))); got != `""` {
			t.Errorf(`description = %s, want ""`, got)
		}
	})
	t.Run("absent description -> empty string", func(t *testing.T) {
		if got := desc(normalizePortalRead([]byte(`{"result":{"id":"p"}}`))); got != `""` {
			t.Errorf(`description = %s, want ""`, got)
		}
	})
	t.Run("real description preserved", func(t *testing.T) {
		if got := desc(normalizePortalRead([]byte(`{"result":{"id":"p","description":"hello"}}`))); got != `"hello"` {
			t.Errorf(`description = %s, want "hello"`, got)
		}
	})
}

func TestPreserveEmptyServerOverrides(t *testing.T) {
	ctx := context.Background()
	empty := []*ZeroTrustAccessAIControlsMcpPortalServersUpdatedToolsModel{}
	mk := func(tools *[]*ZeroTrustAccessAIControlsMcpPortalServersUpdatedToolsModel) customfield.NestedObjectSet[ZeroTrustAccessAIControlsMcpPortalServersModel] {
		s, d := customfield.NewObjectSet(ctx, []ZeroTrustAccessAIControlsMcpPortalServersModel{{
			ServerID:        types.StringValue("a"),
			DefaultDisabled: types.BoolValue(false),
			OnBehalf:        types.BoolValue(false),
			UpdatedTools:    tools,
		}})
		if d.HasError() {
			t.Fatalf("NewObjectSet: %v", d)
		}
		return s
	}

	// decoded [] vs prior null (omitted config) -> keep null.
	out, d := preserveEmptyServerOverrides(ctx, mk(&empty), mk(nil))
	if d.HasError() {
		t.Fatalf("diags: %v", d)
	}
	got, _ := out.AsStructSliceT(ctx)
	if got[0].UpdatedTools != nil {
		t.Errorf("updated_tools = %v, want nil (prior form)", got[0].UpdatedTools)
	}

	// decoded [] vs prior [] -> unchanged.
	out, _ = preserveEmptyServerOverrides(ctx, mk(&empty), mk(&empty))
	got, _ = out.AsStructSliceT(ctx)
	if got[0].UpdatedTools == nil {
		t.Errorf("updated_tools = nil, want []")
	}
}
