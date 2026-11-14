package bot_management

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func nullModel() BotManagementModel {
	return BotManagementModel{
		AIAgents: customfield.NullObject[BotManagementAIAgentsModel](context.Background()),
	}
}

func marshalBody(t *testing.T, m BotManagementAPIModel) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestToAPIModel_UnconfiguredAITrainingOmitted(t *testing.T) {
	state := nullModel()
	state.AITraining = types.StringValue("disallow")
	state.AIBotsProtection = types.StringValue("disabled")

	plan := state
	plan.AIBotsProtection = types.StringValue("block")

	config := nullModel()
	config.AIBotsProtection = types.StringValue("block")

	body := marshalBody(t, plan.ToAPIModel(&config, &state))
	if _, ok := body["ai_training"]; ok {
		t.Errorf("ai_training must not be sent when unconfigured and unchanged: %v", body)
	}
	if body["ai_bots_protection"] != "block" {
		t.Errorf("ai_bots_protection = %v, want block", body["ai_bots_protection"])
	}
}

func TestToAPIModel_NeverSendsUsingLatestModel(t *testing.T) {
	state := nullModel()
	state.UsingLatestModel = types.BoolValue(true)

	plan := state
	plan.UsingLatestModel = types.BoolValue(false)

	config := nullModel()
	config.UsingLatestModel = types.BoolValue(false)

	for name, body := range map[string]map[string]any{
		"create": marshalBody(t, plan.ToAPIModel(&config, nil)),
		"update": marshalBody(t, plan.ToAPIModel(&config, &state)),
	} {
		if _, ok := body["using_latest_model"]; ok {
			t.Errorf("%s: using_latest_model must never be sent: %v", name, body)
		}
		if _, ok := body["stale_zone_configuration"]; ok {
			t.Errorf("%s: stale_zone_configuration must never be sent: %v", name, body)
		}
	}
}

func TestToAPIModel_ConfiguredAITrainingSent(t *testing.T) {
	state := nullModel()
	state.AITraining = types.StringValue("allow")

	plan := state
	config := nullModel()
	config.AITraining = types.StringValue("allow")

	body := marshalBody(t, plan.ToAPIModel(&config, &state))
	if body["ai_training"] != "allow" {
		t.Errorf("configured ai_training must be sent even when unchanged: %v", body)
	}
}

func TestToAPIModel_CreateOnlyConfigured(t *testing.T) {
	plan := nullModel()
	plan.EnableJS = types.BoolValue(true)
	plan.FightMode = types.BoolValue(false)
	plan.AITraining = types.StringValue("disallow")

	config := nullModel()
	config.EnableJS = types.BoolValue(true)

	body := marshalBody(t, plan.ToAPIModel(&config, nil))
	if len(body) != 1 || body["enable_js"] != true {
		t.Errorf("create body = %v, want only enable_js", body)
	}
}

func TestToAPIModel_ChangedVsPriorSent(t *testing.T) {
	state := nullModel()
	state.FightMode = types.BoolValue(false)
	state.EnableJS = types.BoolValue(true)

	plan := state
	plan.FightMode = types.BoolValue(true)

	config := nullModel()

	body := marshalBody(t, plan.ToAPIModel(&config, &state))
	if body["fight_mode"] != true {
		t.Errorf("changed fight_mode must be sent: %v", body)
	}
	if _, ok := body["enable_js"]; ok {
		t.Errorf("unchanged unconfigured enable_js must not be sent: %v", body)
	}
}

func TestToAPIModel_AIAgentsPartialBlock(t *testing.T) {
	ctx := context.Background()
	agents := BotManagementAIAgentsModel{
		AnthropicAgent: types.StringValue("allow"),
		GoogleAgent:    types.StringValue("block"),
		Instinct:       types.StringNull(),
		Muse:           types.StringNull(),
		OpenAIAgent:    types.StringNull(),
	}
	state := nullModel()
	state.AIAgents = customfield.NewObjectMust(ctx, &agents)

	plan := state
	config := nullModel()
	cfgAgents := BotManagementAIAgentsModel{
		AnthropicAgent: types.StringNull(),
		GoogleAgent:    types.StringValue("block"),
		Instinct:       types.StringNull(),
		Muse:           types.StringNull(),
		OpenAIAgent:    types.StringNull(),
	}
	config.AIAgents = customfield.NewObjectMust(ctx, &cfgAgents)

	body := marshalBody(t, plan.ToAPIModel(&config, &state))
	block, ok := body["ai_agents"].(map[string]any)
	if !ok {
		t.Fatalf("ai_agents block missing: %v", body)
	}
	if len(block) != 1 || block["google_agent"] != "block" {
		t.Errorf("ai_agents = %v, want only google_agent", block)
	}

	// Nothing configured or changed: block omitted.
	empty := nullModel()
	body = marshalBody(t, plan.ToAPIModel(&empty, &state))
	if _, ok := body["ai_agents"]; ok {
		t.Errorf("ai_agents must be omitted when no sub-field qualifies: %v", body)
	}
}
