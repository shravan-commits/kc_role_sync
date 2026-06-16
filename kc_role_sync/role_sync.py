from __future__ import annotations

import frappe
import requests
from frappe.utils.password import get_decrypted_password

NO_PROXY = {"http": "", "https": ""}

# Keycloak built-in roles that should never be assigned as Frappe roles
_INTERNAL_ROLES = frozenset([
	"offline_access",
	"uma_authorization",
	"manage-account",
	"manage-account-links",
	"view-profile",
	"frappe_user",
])


def sync_on_user_creation(doc, method=None):
	"""
	User.after_insert — fires the first time a user logs in via Keycloak SSO
	and Frappe creates their account. Assigns Keycloak roles immediately.
	"""
	_do_sync(doc.name)
	# Stamp cache so on_session_creation skips the duplicate call right after
	frappe.cache().set_value(f"kc_role_sync:{doc.name}", 1, expires_in_sec=600)


def sync_on_session_creation():
	"""
	Fires on every new Frappe session.  Rate-limited with a 10-minute Redis
	cache so we don't hammer Keycloak on every page refresh.  Useful for
	picking up role changes in Keycloak after the user already exists.
	"""
	user = frappe.session.user
	if not user or user in ("Guest", "Administrator"):
		return

	cache_key = f"kc_role_sync:{user}"
	if frappe.cache().get_value(cache_key):
		return

	_do_sync(user)
	frappe.cache().set_value(cache_key, 1, expires_in_sec=600)


# ── core sync ────────────────────────────────────────────────────────────────

def _do_sync(email: str) -> None:
	try:
		clients = _get_keycloak_clients()
		if not clients:
			frappe.logger().info(f"KC_ROLE_SYNC: No Social Login Keys found for site — skipping {email}")
			return

		frappe_user = frappe.get_doc("User", email)
		existing_roles = {r.role for r in frappe_user.get("roles", [])}

		new_roles: list[str] = []
		for client in clients:
			new_roles.extend(_get_keycloak_roles(client, email))

		added = False
		for role in set(new_roles):
			if frappe.db.exists("Role", role) and role not in existing_roles:
				frappe_user.append("roles", {"role": role})
				frappe.logger().info(f"KC_ROLE_SYNC: Assigning role '{role}' to {email}")
				added = True

		if added:
			frappe_user.save(ignore_permissions=True)
			frappe.db.commit()
			frappe.logger().info(f"KC_ROLE_SYNC: Roles saved for {email}")
		else:
			frappe.logger().info(f"KC_ROLE_SYNC: No new roles to assign for {email}")

	except Exception as exc:
		frappe.logger().error(f"KC_ROLE_SYNC: Error syncing roles for {email}: {exc}")


# ── Keycloak helpers ─────────────────────────────────────────────────────────

def _get_keycloak_clients() -> list[dict]:
	return frappe.get_all(
		"Social Login Key",
		filters={"enable_social_login": 1},
		fields=["name", "client_id", "base_url", "api_endpoint"],
	)


def _get_keycloak_roles(client: dict, email: str) -> list[str]:
	try:
		base_url = (client.get("base_url") or "").rstrip("/")
		client_id = client.get("client_id")
		api_endpoint = client.get("api_endpoint") or ""
		client_secret = get_decrypted_password("Social Login Key", client["name"], "client_secret")

		realm = _extract_realm(api_endpoint)
		if not realm:
			frappe.logger().warning(f"KC_ROLE_SYNC: Cannot extract realm from api_endpoint '{api_endpoint}'")
			return []

		token = _get_admin_token(base_url, realm, client_id, client_secret)
		if not token:
			frappe.logger().warning(f"KC_ROLE_SYNC: Could not get admin token for realm '{realm}'")
			return []

		# Locate user in Keycloak by email
		resp = requests.get(
			f"{base_url}/admin/realms/{realm}/users",
			params={"email": email, "exact": "true"},
			headers={"Authorization": f"Bearer {token}"},
			timeout=10,
			proxies=NO_PROXY,
		)
		users = resp.json() if resp.status_code == 200 else []
		if not users:
			frappe.logger().info(f"KC_ROLE_SYNC: User {email} not found in Keycloak realm '{realm}'")
			return []

		kc_user_id = users[0]["id"]

		# Cache Keycloak sub (user id) → email so the back-channel logout receiver
		# can map Keycloak's logout token (keyed by `sub`) to this user without an
		# extra admin lookup. See kc_role_sync/backchannel.py.
		frappe.cache().set_value(f"kc_sub:{kc_user_id}", email, expires_in_sec=86400)

		# Fetch all role mappings (realm + client-specific)
		resp = requests.get(
			f"{base_url}/admin/realms/{realm}/users/{kc_user_id}/role-mappings",
			headers={"Authorization": f"Bearer {token}"},
			timeout=10,
			proxies=NO_PROXY,
		)
		mappings = resp.json() if resp.status_code == 200 else {}

		roles: list[str] = []

		# Realm-level roles
		for r in mappings.get("realmMappings", []):
			if not _is_internal(r["name"]):
				roles.append(r["name"])

		# Client-specific roles (only for this client)
		client_mappings = mappings.get("clientMappings", {})
		if client_id in client_mappings:
			for r in client_mappings[client_id].get("mappings", []):
				roles.append(r["name"])

		frappe.logger().info(f"KC_ROLE_SYNC: Found Keycloak roles for {email}: {roles}")
		return roles

	except Exception as exc:
		frappe.logger().error(f"KC_ROLE_SYNC: _get_keycloak_roles failed for {email}: {exc}")
		return []


def _get_admin_token(base_url: str, realm: str, client_id: str, client_secret: str) -> str | None:
	try:
		resp = requests.post(
			f"{base_url}/realms/{realm}/protocol/openid-connect/token",
			data={
				"grant_type": "client_credentials",
				"client_id": client_id,
				"client_secret": client_secret,
			},
			timeout=10,
			proxies=NO_PROXY,
		)
		return resp.json().get("access_token")
	except Exception as exc:
		frappe.logger().error(f"KC_ROLE_SYNC: Admin token request failed: {exc}")
		return None


def _extract_realm(api_endpoint: str) -> str | None:
	try:
		parts = api_endpoint.split("/realms/")
		if len(parts) > 1:
			return parts[1].split("/")[0]
	except Exception:
		pass
	return None


def _is_internal(role_name: str) -> bool:
	return role_name in _INTERNAL_ROLES or role_name.startswith("default-roles-")
