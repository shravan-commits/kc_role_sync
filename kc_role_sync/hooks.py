app_name = "kc_role_sync"
app_title = "KC Role Sync"
app_publisher = "Kalyan"
app_description = "Auto-assign Keycloak roles to Frappe users on first SSO login"
app_email = "shravan.a.sahi.ext@kalyanj.onmicrosoft.com"
app_license = "MIT"

doc_events = {
	"User": {
		# Fires when user is created for the first time via SSO
		"after_insert": "kc_role_sync.role_sync.sync_on_user_creation",
	}
}

# Also fires on every new session — picks up role changes in Keycloak after first login
# Rate-limited via Redis cache (10 min TTL) to avoid repeated Keycloak API calls
on_session_creation = "kc_role_sync.role_sync.sync_on_session_creation"
