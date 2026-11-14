resource "cloudflare_zero_trust_access_identity_provider" "%[2]s" {
  account_id = "%[1]s"
  name       = "%[2]s"
  type       = "cloudflare"
  config     = {}
  scim_config = {
    enabled                  = false
    identity_update_behavior = "%[3]s"
  }
}
