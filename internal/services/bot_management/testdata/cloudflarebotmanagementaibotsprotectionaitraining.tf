
resource "cloudflare_bot_management" "%[1]s" {
	zone_id = "%[2]s"

	ai_bots_protection = "%[3]s"
	ai_training        = "%[4]s"
}
