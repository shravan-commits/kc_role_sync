# kc_role_sync

Lightweight Frappe app — no doctypes, no exposed data.

Automatically assigns Keycloak roles to a Frappe user when they log in via
Keycloak SSO for the first time.  Also re-syncs roles on subsequent logins
(rate-limited to once every 10 minutes via Redis cache).

## How it works

1. User logs into the client Frappe site via Keycloak SSO
2. Frappe creates the User record (`after_insert` fires)
3. This app calls the Keycloak Admin API using the **existing Social Login Key**
   already configured on that site — no extra setup needed
4. Fetches the user's realm roles + client-specific roles from Keycloak
5. Assigns any roles that exist as Frappe Roles on this site

Only roles that already exist as Role doctypes on the Frappe site are assigned.
Keycloak internal roles (`offline_access`, `uma_authorization`, etc.) are skipped.

## Installation

On each client Frappe site:

```bash
# From your bench directory
bench get-app kc_role_sync /path/to/kc_role_sync   # or git URL
bench --site your-client-site.local install-app kc_role_sync
```

## Requirements

- The site must already have a **Social Login Key** configured for Keycloak SSO
  (if SSO login works, this is already in place)
- The Keycloak client used for SSO must have **Service Accounts Enabled**
  so client-credentials token exchange works
- Roles must exist as **Role** doctypes on the Frappe site to be assignable
