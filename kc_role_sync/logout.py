"""
Client-side logout — runs on every client app (this is the app clients install).

Problem this fixes: clicking "Log out" inside a client app (e.g. DATIM) only
clears that app's local Frappe session. Keycloak's SSO session stays alive,
so the central portal and every other client app (e.g. frappe_client_one)
remain logged in. Keycloak's backchannel logout fan-out (received by every
client's kc_role_sync.backchannel.backchannel_logout) only fires when the
Keycloak SSO session itself is actually ended — and that only happens via an
RP-initiated logout hitting Keycloak's end_session endpoint.

So: on local Frappe logout, redirect through Keycloak's end_session endpoint
instead of just dropping the session. Keycloak then fans the backchannel
logout token out to every other registered client (including the central
portal), and finally lands the browser back on the central portal's
"no access" screen.

Central portal landing URL is read from site_config.json:
    "kc_central_portal_url": "http://10.150.48.12:8001"
Falls back to redirecting to this site's own login page if not configured,
so a client app still gets local logout behavior even before that key is set.
"""
from __future__ import annotations

import frappe


def on_logout():
	try:
		client_id, base_url, realm = _resolve_this_client()
		if not base_url or not realm or not client_id:
			frappe.logger().warning(
				"KC_LOGOUT: no usable Social Login Key (base_url/realm/client_id) — "
				"falling back to local-only logout"
			)
			return

		portal_url = (frappe.conf.get("kc_central_portal_url") or "").rstrip("/")
		post_logout_redirect_uri = (
			f"{portal_url}/kalyan/applications?no_access=1"
			if portal_url
			else frappe.utils.get_url("/login")
		)

		frappe.local.response["redirect_to"] = (
			f"{base_url}/realms/{realm}/protocol/openid-connect/logout"
			f"?client_id={client_id}"
			f"&post_logout_redirect_uri={post_logout_redirect_uri}"
		)
	except Exception as exc:
		frappe.logger().error(f"KC_LOGOUT: on_logout failed: {exc}")


def _resolve_this_client():
	"""This site's own Keycloak client_id/base_url/realm, from its Social Login Key."""
	from kc_role_sync.role_sync import _get_keycloak_clients, _extract_realm

	clients = _get_keycloak_clients()
	if not clients:
		return None, None, None

	c = clients[0]
	base_url = (c.get("base_url") or "").rstrip("/")
	realm = _extract_realm(c.get("api_endpoint") or "")
	return c.get("client_id"), base_url, realm
