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

NO_PROXY = {"http": "", "https": ""}


def on_logout():
	try:
		# Identity is still available here — Frappe runs the on_logout trigger BEFORE it
		# deletes the session (see frappe/auth.py LoginManager.logout).
		user = frappe.session.user if frappe.session.user != "Guest" else None

		# Terminate EVERY Keycloak SSO session for this user via the admin API. A plain
		# RP-initiated logout to the end_session endpoint only ends the one session tied to
		# its id_token (which we don't have here) — and a portal login spawns several
		# sessions, so the SSO session would survive and the back-channel fan-out would never
		# fire. Killing all of the user's sessions makes Keycloak back-channel-logout every
		# registered client (the central portal and all other apps) in one shot.
		if user:
			_terminate_all_keycloak_sessions(user)

		portal_url = (frappe.conf.get("kc_central_portal_url") or "").rstrip("/")
		post_logout_redirect_uri = (
			f"{portal_url}/kalyan/applications?no_access=1"
			if portal_url
			else frappe.utils.get_url("/login")
		)

		# Sessions are already gone server-side, so land the browser straight on the central
		# portal's public no-access page. No dependency on the Keycloak end_session endpoint
		# (which without an id_token_hint would not reliably end the session anyway).
		frappe.local.response["redirect_to"] = post_logout_redirect_uri
	except Exception as exc:
		frappe.logger().error(f"KC_LOGOUT: on_logout failed: {exc}")


def _terminate_all_keycloak_sessions(user: str) -> bool:
	"""End every Keycloak SSO session for `user` via the admin API (best-effort).

	Uses this site's Social Login Key client service-account token, resolves the Keycloak
	user by email then by username (employee code), and calls the admin user-logout endpoint
	— which kills all of the user's sessions and triggers back-channel logout to every
	participating client. Never raises; returns True only on a confirmed logout.
	"""
	import requests
	from frappe.utils.password import get_decrypted_password
	from kc_role_sync.role_sync import (
		_get_keycloak_clients, _get_admin_token, _extract_realm,
	)

	for c in _get_keycloak_clients():
		base_url = (c.get("base_url") or "").rstrip("/")
		realm = _extract_realm(c.get("api_endpoint") or "")
		client_id = c.get("client_id")
		if not base_url or not realm or not client_id:
			continue
		try:
			secret = get_decrypted_password("Social Login Key", c["name"], "client_secret")
			token = _get_admin_token(base_url, realm, client_id, secret)
			if not token:
				continue
			hdr = {"Authorization": f"Bearer {token}"}
			admin = f"{base_url}/admin/realms/{realm}/users"
			# Resolve the Keycloak user id: email first, then username (employee code).
			kc_id = None
			for param in ("email", "username"):
				r = requests.get(admin, params={param: user, "exact": "true"},
				                 headers=hdr, proxies=NO_PROXY, timeout=10)
				users = r.json() if r.ok else []
				if users:
					kc_id = users[0].get("id")
					break
			if not kc_id:
				frappe.logger().warning(f"KC_LOGOUT: Keycloak user not found for {user}")
				continue
			lr = requests.post(f"{admin}/{kc_id}/logout", headers=hdr,
			                   proxies=NO_PROXY, timeout=15)
			if lr.status_code in (200, 204):
				frappe.logger().info(f"KC_LOGOUT: terminated all Keycloak sessions for {user}")
				return True
			frappe.logger().warning(
				f"KC_LOGOUT: admin logout returned {lr.status_code} for {user} "
				f"(client {client_id} service account may lack manage-users)"
			)
		except Exception as exc:
			frappe.logger().error(f"KC_LOGOUT: session termination failed via {client_id}: {exc}")
	return False


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
