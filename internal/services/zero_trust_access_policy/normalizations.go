package zero_trust_access_policy

import (
	"context"
	"reflect"
	"strings"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

type IsNull interface {
	IsNull() bool
}

func normalizeEmptyAndNullSlice[T any](data **[]T, stateData *[]T) {
	if (*data != nil && len(**data) != 0) || (stateData != nil && len(*stateData) != 0) {
		return
	}
	*data = stateData
}

type SetValueInterface interface {
	IsNull() bool
	Elements() []attr.Value
}

func normalizeEmptyAndNullNestedObjectSet[T SetValueInterface](data *T, stateData T) {
	if (*data).IsNull() && stateData.IsNull() {
		return
	}
	if (!(*data).IsNull() && len((*data).Elements()) != 0) || (!stateData.IsNull() && len(stateData.Elements()) != 0) {
		return
	}
	*data = stateData
}

func normalizeFalseAndNullBool(data *basetypes.BoolValue, stateData basetypes.BoolValue) {
	if data.ValueBool() || stateData.ValueBool() {
		return
	}
	*data = stateData
}

// Normalizing function to ensure consistency between the state/plan and the meaning of the API response.
// Alters the API response before applying it to the state by laxing equalities between null & zero-value
// for some attributes, and nullifies fields that terraform should not be saving in the state.
func normalizeReadZeroTrustAccessPolicyAPIData(ctx context.Context, data, sourceData *ZeroTrustAccessPolicyModel) diag.Diagnostics {
	diags := make(diag.Diagnostics, 0)
	diags.Append(pruneEmptyConditionSelectors(ctx, data)...)

	// For rule fields, if they were null/unknown in the source (plan/state) and the API returned empty sets,
	// convert them back to null to prevent "inconsistent result after apply" errors.
	// Unknown is treated like null here because during Create, computed+optional fields that the user
	// didn't set come in as Unknown from the plan.
	if (sourceData.Include.IsNull() || sourceData.Include.IsUnknown()) && !data.Include.IsNull() && len(data.Include.Elements()) == 0 {
		data.Include = customfield.NullObjectSet[ZeroTrustAccessPolicyIncludeModel](ctx)
	}
	if (sourceData.Require.IsNull() || sourceData.Require.IsUnknown()) && !data.Require.IsNull() && len(data.Require.Elements()) == 0 {
		data.Require = customfield.NullObjectSet[ZeroTrustAccessPolicyRequireModel](ctx)
	}
	if (sourceData.Exclude.IsNull() || sourceData.Exclude.IsUnknown()) && !data.Exclude.IsNull() && len(data.Exclude.Elements()) == 0 {
		data.Exclude = customfield.NullObjectSet[ZeroTrustAccessPolicyExcludeModel](ctx)
	}

	// For non-empty rule fields, use standard normalization (only when source is known)
	if (!sourceData.Include.IsNull() && !sourceData.Include.IsUnknown()) || (!data.Include.IsNull() && len(data.Include.Elements()) > 0) {
		normalizeEmptyAndNullNestedObjectSet(&data.Include, sourceData.Include)
	}
	if (!sourceData.Require.IsNull() && !sourceData.Require.IsUnknown()) || (!data.Require.IsNull() && len(data.Require.Elements()) > 0) {
		normalizeEmptyAndNullNestedObjectSet(&data.Require, sourceData.Require)
	}
	if (!sourceData.Exclude.IsNull() && !sourceData.Exclude.IsUnknown()) || (!data.Exclude.IsNull() && len(data.Exclude.Elements()) > 0) {
		normalizeEmptyAndNullNestedObjectSet(&data.Exclude, sourceData.Exclude)
	}

	// Normalize session_duration — when the user explicitly sets session_duration = ""
	// (meaning "same as application session timeout"), the API's Get response may omit
	// the field (returning null) or return the default "24h" instead. Preserve the user's
	// empty-string intention to prevent perpetual diffs.
	if !sourceData.SessionDuration.IsNull() && !sourceData.SessionDuration.IsUnknown() &&
		sourceData.SessionDuration.ValueString() == "" &&
		(data.SessionDuration.IsNull() || data.SessionDuration.ValueString() != "") {
		data.SessionDuration = sourceData.SessionDuration
	}

	// For other fields, use the original normalization logic
	normalizeEmptyAndNullSlice(&data.ApprovalGroups, sourceData.ApprovalGroups)
	normalizeFalseAndNullBool(&data.PurposeJustificationRequired, sourceData.PurposeJustificationRequired)
	normalizeFalseAndNullBool(&data.ApprovalRequired, sourceData.ApprovalRequired)
	normalizeFalseAndNullBool(&data.IsolationRequired, sourceData.IsolationRequired)

	// Normalize clipboard arrays inside connection_rules.rdp — the API omits empty arrays
	// due to omitempty, so [] in state vs null from API should not cause drift.
	if data.ConnectionRules != nil && sourceData.ConnectionRules != nil {
		if data.ConnectionRules.RDP != nil && sourceData.ConnectionRules.RDP != nil {
			normalizeEmptyAndNullSlice(&data.ConnectionRules.RDP.AllowedClipboardLocalToRemoteFormats, sourceData.ConnectionRules.RDP.AllowedClipboardLocalToRemoteFormats)
			normalizeEmptyAndNullSlice(&data.ConnectionRules.RDP.AllowedClipboardRemoteToLocalFormats, sourceData.ConnectionRules.RDP.AllowedClipboardRemoteToLocalFormats)
		}
	}

	// Normalize mfa_config inner fields — when users configure mfa_config without mfa_disabled,
	// the API returns mfa_disabled: false which would otherwise drift against null in state.
	// Same for an empty allowed_authenticators list.
	if data.MfaConfig != nil && sourceData.MfaConfig != nil {
		normalizeEmptyAndNullSlice(&data.MfaConfig.AllowedAuthenticators, sourceData.MfaConfig.AllowedAuthenticators)
		normalizeFalseAndNullBool(&data.MfaConfig.MfaDisabled, sourceData.MfaConfig.MfaDisabled)
	}

	return diags
}

// The API returns every rule in full, in its own order. Decoding onto the prior
// state merges the response into the existing set elements by index, so when the
// order differs, selectors from one rule leak into another. Clear the prior rules
// so they decode fresh.
func clearPriorRules(ctx context.Context, data *ZeroTrustAccessPolicyModel) {
	data.Include = customfield.NullObjectSet[ZeroTrustAccessPolicyIncludeModel](ctx)
	data.Exclude = customfield.NullObjectSet[ZeroTrustAccessPolicyExcludeModel](ctx)
	data.Require = customfield.NullObjectSet[ZeroTrustAccessPolicyRequireModel](ctx)
}

func pruneEmptyConditionSelectors(ctx context.Context, data *ZeroTrustAccessPolicyModel) diag.Diagnostics {
	diags := make(diag.Diagnostics, 0)
	diags.Append(pruneEmptyIncludeSelectors(ctx, &data.Include)...)
	diags.Append(pruneEmptyExcludeSelectors(ctx, &data.Exclude)...)
	diags.Append(pruneEmptyRequireSelectors(ctx, &data.Require)...)
	return diags
}

func pruneEmptyIncludeSelectors(ctx context.Context, set *customfield.NestedObjectSet[ZeroTrustAccessPolicyIncludeModel]) diag.Diagnostics {
	diags := make(diag.Diagnostics, 0)
	if set.IsNull() || set.IsUnknown() {
		return diags
	}

	conditions, d := set.AsStructSliceT(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	filtered := make([]ZeroTrustAccessPolicyIncludeModel, 0, len(conditions))
	for _, c := range conditions {
		nullEmptyIncludeConditionSelectors(&c)

		if reflect.DeepEqual(c, ZeroTrustAccessPolicyIncludeModel{}) {
			continue
		}
		filtered = append(filtered, c)
	}

	next, d := customfield.NewObjectSet(ctx, filtered)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}
	*set = next
	return diags
}

func pruneEmptyExcludeSelectors(ctx context.Context, set *customfield.NestedObjectSet[ZeroTrustAccessPolicyExcludeModel]) diag.Diagnostics {
	diags := make(diag.Diagnostics, 0)
	if set.IsNull() || set.IsUnknown() {
		return diags
	}

	conditions, d := set.AsStructSliceT(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	filtered := make([]ZeroTrustAccessPolicyExcludeModel, 0, len(conditions))
	for _, c := range conditions {
		nullEmptyExcludeConditionSelectors(&c)

		if reflect.DeepEqual(c, ZeroTrustAccessPolicyExcludeModel{}) {
			continue
		}
		filtered = append(filtered, c)
	}

	next, d := customfield.NewObjectSet(ctx, filtered)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}
	*set = next
	return diags
}

func pruneEmptyRequireSelectors(ctx context.Context, set *customfield.NestedObjectSet[ZeroTrustAccessPolicyRequireModel]) diag.Diagnostics {
	diags := make(diag.Diagnostics, 0)
	if set.IsNull() || set.IsUnknown() {
		return diags
	}

	conditions, d := set.AsStructSliceT(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	filtered := make([]ZeroTrustAccessPolicyRequireModel, 0, len(conditions))
	for _, c := range conditions {
		nullEmptyRequireConditionSelectors(&c)

		if reflect.DeepEqual(c, ZeroTrustAccessPolicyRequireModel{}) {
			continue
		}
		filtered = append(filtered, c)
	}

	next, d := customfield.NewObjectSet(ctx, filtered)
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}
	*set = next
	return diags
}

func isNullUnknownOrEmptyString(v basetypes.StringValue) bool {
	if v.IsNull() || v.IsUnknown() {
		return true
	}
	return strings.TrimSpace(v.ValueString()) == ""
}

// A real selector always has a populated content field, so an object selector
// with all content empty is a decode artifact stamped from a sibling rule.
// Content-less selectors (everyone, certificate, any_valid_service_token,
// cloudflare_account_member) are legitimately empty and left untouched.
func nullEmptyIncludeConditionSelectors(c *ZeroTrustAccessPolicyIncludeModel) {
	if c.Group != nil && isNullUnknownOrEmptyString(c.Group.ID) {
		c.Group = nil
	}
	if c.AuthContext != nil && allNullUnknownOrEmpty(c.AuthContext.ID, c.AuthContext.AcID, c.AuthContext.IdentityProviderID) {
		c.AuthContext = nil
	}
	if c.AuthMethod != nil && isNullUnknownOrEmptyString(c.AuthMethod.AuthMethod) {
		c.AuthMethod = nil
	}
	if c.AzureAD != nil && allNullUnknownOrEmpty(c.AzureAD.ID, c.AzureAD.IdentityProviderID) {
		c.AzureAD = nil
	}
	if c.CommonName != nil && isNullUnknownOrEmptyString(c.CommonName.CommonName) {
		c.CommonName = nil
	}
	if c.Geo != nil && isNullUnknownOrEmptyString(c.Geo.CountryCode) {
		c.Geo = nil
	}
	if c.DevicePosture != nil && isNullUnknownOrEmptyString(c.DevicePosture.IntegrationUID) {
		c.DevicePosture = nil
	}
	if c.EmailDomain != nil && isNullUnknownOrEmptyString(c.EmailDomain.Domain) {
		c.EmailDomain = nil
	}
	if c.EmailList != nil && isNullUnknownOrEmptyString(c.EmailList.ID) {
		c.EmailList = nil
	}
	if c.Email != nil && isNullUnknownOrEmptyString(c.Email.Email) {
		c.Email = nil
	}
	if c.ExternalEvaluation != nil && allNullUnknownOrEmpty(c.ExternalEvaluation.EvaluateURL, c.ExternalEvaluation.KeysURL) {
		c.ExternalEvaluation = nil
	}
	if c.GitHubOrganization != nil && allNullUnknownOrEmpty(c.GitHubOrganization.IdentityProviderID, c.GitHubOrganization.Name, c.GitHubOrganization.Team) {
		c.GitHubOrganization = nil
	}
	if c.GSuite != nil && allNullUnknownOrEmpty(c.GSuite.Email, c.GSuite.IdentityProviderID) {
		c.GSuite = nil
	}
	if c.LoginMethod != nil && isNullUnknownOrEmptyString(c.LoginMethod.ID) {
		c.LoginMethod = nil
	}
	if c.IPList != nil && isNullUnknownOrEmptyString(c.IPList.ID) {
		c.IPList = nil
	}
	if c.IP != nil && isNullUnknownOrEmptyString(c.IP.IP) {
		c.IP = nil
	}
	if c.Okta != nil && allNullUnknownOrEmpty(c.Okta.IdentityProviderID, c.Okta.Name) {
		c.Okta = nil
	}
	if c.SAML != nil && allNullUnknownOrEmpty(c.SAML.AttributeName, c.SAML.AttributeValue, c.SAML.IdentityProviderID) {
		c.SAML = nil
	}
	if c.OIDC != nil && allNullUnknownOrEmpty(c.OIDC.ClaimName, c.OIDC.ClaimValue, c.OIDC.IdentityProviderID) {
		c.OIDC = nil
	}
	if c.ServiceToken != nil && isNullUnknownOrEmptyString(c.ServiceToken.TokenID) {
		c.ServiceToken = nil
	}
	if c.ServiceTokenTag != nil && allNullUnknownOrEmpty(c.ServiceTokenTag.Key, c.ServiceTokenTag.Value) {
		c.ServiceTokenTag = nil
	}
	if c.LinkedAppToken != nil && isNullUnknownOrEmptyString(c.LinkedAppToken.AppUID) {
		c.LinkedAppToken = nil
	}
	if c.UserRiskScore != nil && (c.UserRiskScore.UserRiskScore == nil || len(*c.UserRiskScore.UserRiskScore) == 0) {
		c.UserRiskScore = nil
	}
}

func nullEmptyExcludeConditionSelectors(c *ZeroTrustAccessPolicyExcludeModel) {
	if c.Group != nil && isNullUnknownOrEmptyString(c.Group.ID) {
		c.Group = nil
	}
	if c.AuthContext != nil && allNullUnknownOrEmpty(c.AuthContext.ID, c.AuthContext.AcID, c.AuthContext.IdentityProviderID) {
		c.AuthContext = nil
	}
	if c.AuthMethod != nil && isNullUnknownOrEmptyString(c.AuthMethod.AuthMethod) {
		c.AuthMethod = nil
	}
	if c.AzureAD != nil && allNullUnknownOrEmpty(c.AzureAD.ID, c.AzureAD.IdentityProviderID) {
		c.AzureAD = nil
	}
	if c.CommonName != nil && isNullUnknownOrEmptyString(c.CommonName.CommonName) {
		c.CommonName = nil
	}
	if c.Geo != nil && isNullUnknownOrEmptyString(c.Geo.CountryCode) {
		c.Geo = nil
	}
	if c.DevicePosture != nil && isNullUnknownOrEmptyString(c.DevicePosture.IntegrationUID) {
		c.DevicePosture = nil
	}
	if c.EmailDomain != nil && isNullUnknownOrEmptyString(c.EmailDomain.Domain) {
		c.EmailDomain = nil
	}
	if c.EmailList != nil && isNullUnknownOrEmptyString(c.EmailList.ID) {
		c.EmailList = nil
	}
	if c.Email != nil && isNullUnknownOrEmptyString(c.Email.Email) {
		c.Email = nil
	}
	if c.ExternalEvaluation != nil && allNullUnknownOrEmpty(c.ExternalEvaluation.EvaluateURL, c.ExternalEvaluation.KeysURL) {
		c.ExternalEvaluation = nil
	}
	if c.GitHubOrganization != nil && allNullUnknownOrEmpty(c.GitHubOrganization.IdentityProviderID, c.GitHubOrganization.Name, c.GitHubOrganization.Team) {
		c.GitHubOrganization = nil
	}
	if c.GSuite != nil && allNullUnknownOrEmpty(c.GSuite.Email, c.GSuite.IdentityProviderID) {
		c.GSuite = nil
	}
	if c.LoginMethod != nil && isNullUnknownOrEmptyString(c.LoginMethod.ID) {
		c.LoginMethod = nil
	}
	if c.IPList != nil && isNullUnknownOrEmptyString(c.IPList.ID) {
		c.IPList = nil
	}
	if c.IP != nil && isNullUnknownOrEmptyString(c.IP.IP) {
		c.IP = nil
	}
	if c.Okta != nil && allNullUnknownOrEmpty(c.Okta.IdentityProviderID, c.Okta.Name) {
		c.Okta = nil
	}
	if c.SAML != nil && allNullUnknownOrEmpty(c.SAML.AttributeName, c.SAML.AttributeValue, c.SAML.IdentityProviderID) {
		c.SAML = nil
	}
	if c.OIDC != nil && allNullUnknownOrEmpty(c.OIDC.ClaimName, c.OIDC.ClaimValue, c.OIDC.IdentityProviderID) {
		c.OIDC = nil
	}
	if c.ServiceToken != nil && isNullUnknownOrEmptyString(c.ServiceToken.TokenID) {
		c.ServiceToken = nil
	}
	if c.ServiceTokenTag != nil && allNullUnknownOrEmpty(c.ServiceTokenTag.Key, c.ServiceTokenTag.Value) {
		c.ServiceTokenTag = nil
	}
	if c.LinkedAppToken != nil && isNullUnknownOrEmptyString(c.LinkedAppToken.AppUID) {
		c.LinkedAppToken = nil
	}
	if c.UserRiskScore != nil && (c.UserRiskScore.UserRiskScore == nil || len(*c.UserRiskScore.UserRiskScore) == 0) {
		c.UserRiskScore = nil
	}
}

func nullEmptyRequireConditionSelectors(c *ZeroTrustAccessPolicyRequireModel) {
	if c.Group != nil && isNullUnknownOrEmptyString(c.Group.ID) {
		c.Group = nil
	}
	if c.AuthContext != nil && allNullUnknownOrEmpty(c.AuthContext.ID, c.AuthContext.AcID, c.AuthContext.IdentityProviderID) {
		c.AuthContext = nil
	}
	if c.AuthMethod != nil && isNullUnknownOrEmptyString(c.AuthMethod.AuthMethod) {
		c.AuthMethod = nil
	}
	if c.AzureAD != nil && allNullUnknownOrEmpty(c.AzureAD.ID, c.AzureAD.IdentityProviderID) {
		c.AzureAD = nil
	}
	if c.CommonName != nil && isNullUnknownOrEmptyString(c.CommonName.CommonName) {
		c.CommonName = nil
	}
	if c.Geo != nil && isNullUnknownOrEmptyString(c.Geo.CountryCode) {
		c.Geo = nil
	}
	if c.DevicePosture != nil && isNullUnknownOrEmptyString(c.DevicePosture.IntegrationUID) {
		c.DevicePosture = nil
	}
	if c.EmailDomain != nil && isNullUnknownOrEmptyString(c.EmailDomain.Domain) {
		c.EmailDomain = nil
	}
	if c.EmailList != nil && isNullUnknownOrEmptyString(c.EmailList.ID) {
		c.EmailList = nil
	}
	if c.Email != nil && isNullUnknownOrEmptyString(c.Email.Email) {
		c.Email = nil
	}
	if c.ExternalEvaluation != nil && allNullUnknownOrEmpty(c.ExternalEvaluation.EvaluateURL, c.ExternalEvaluation.KeysURL) {
		c.ExternalEvaluation = nil
	}
	if c.GitHubOrganization != nil && allNullUnknownOrEmpty(c.GitHubOrganization.IdentityProviderID, c.GitHubOrganization.Name, c.GitHubOrganization.Team) {
		c.GitHubOrganization = nil
	}
	if c.GSuite != nil && allNullUnknownOrEmpty(c.GSuite.Email, c.GSuite.IdentityProviderID) {
		c.GSuite = nil
	}
	if c.LoginMethod != nil && isNullUnknownOrEmptyString(c.LoginMethod.ID) {
		c.LoginMethod = nil
	}
	if c.IPList != nil && isNullUnknownOrEmptyString(c.IPList.ID) {
		c.IPList = nil
	}
	if c.IP != nil && isNullUnknownOrEmptyString(c.IP.IP) {
		c.IP = nil
	}
	if c.Okta != nil && allNullUnknownOrEmpty(c.Okta.IdentityProviderID, c.Okta.Name) {
		c.Okta = nil
	}
	if c.SAML != nil && allNullUnknownOrEmpty(c.SAML.AttributeName, c.SAML.AttributeValue, c.SAML.IdentityProviderID) {
		c.SAML = nil
	}
	if c.OIDC != nil && allNullUnknownOrEmpty(c.OIDC.ClaimName, c.OIDC.ClaimValue, c.OIDC.IdentityProviderID) {
		c.OIDC = nil
	}
	if c.ServiceToken != nil && isNullUnknownOrEmptyString(c.ServiceToken.TokenID) {
		c.ServiceToken = nil
	}
	if c.ServiceTokenTag != nil && allNullUnknownOrEmpty(c.ServiceTokenTag.Key, c.ServiceTokenTag.Value) {
		c.ServiceTokenTag = nil
	}
	if c.LinkedAppToken != nil && isNullUnknownOrEmptyString(c.LinkedAppToken.AppUID) {
		c.LinkedAppToken = nil
	}
	if c.UserRiskScore != nil && (c.UserRiskScore.UserRiskScore == nil || len(*c.UserRiskScore.UserRiskScore) == 0) {
		c.UserRiskScore = nil
	}
}

func allNullUnknownOrEmpty(values ...basetypes.StringValue) bool {
	for _, v := range values {
		if !isNullUnknownOrEmptyString(v) {
			return false
		}
	}
	return true
}

// Specialized normalization for import operations where API omits false boolean values
func normalizeImportZeroTrustAccessPolicyAPIData(ctx context.Context, data *ZeroTrustAccessPolicyModel) diag.Diagnostics {
	diags := make(diag.Diagnostics, 0)
	diags.Append(pruneEmptyConditionSelectors(ctx, data)...)

	if !data.Include.IsNull() && len(data.Include.Elements()) == 0 {
		data.Include = customfield.NullObjectSet[ZeroTrustAccessPolicyIncludeModel](ctx)
	}

	if !data.Require.IsNull() && len(data.Require.Elements()) == 0 {
		data.Require = customfield.NullObjectSet[ZeroTrustAccessPolicyRequireModel](ctx)
	}

	if !data.Exclude.IsNull() && len(data.Exclude.Elements()) == 0 {
		data.Exclude = customfield.NullObjectSet[ZeroTrustAccessPolicyExcludeModel](ctx)
	}

	return diags
}
