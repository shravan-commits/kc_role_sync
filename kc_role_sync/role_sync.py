from __future__ import annotations

import json
import logging

import frappe
import requests
from frappe.utils.password import get_decrypted_password

# Dedicated log file (logs/kc_role_sync.log, bench and site level) instead of
# the shared frappe.log — makes this app's activity easy to tail/grep on its
# own. Also explicitly set to INFO: Frappe's default production log level is
# ERROR, which would otherwise silently drop every info/warning line below,
# leaving only bare error messages with no context on what led to them.
_logger = frappe.logger("kc_role_sync", allow_site=True, file_count=20)
_logger.setLevel(logging.INFO)

# Some deployments sit behind a WAF that silently rejects the default
# python-requests User-Agent (empty/non-JSON body, no clear error) before the
# request ever reaches Keycloak — a browser-like UA avoids that.
_BROWSER_HEADERS = {
	"User-Agent": (
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
		"(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	),
	"Accept": "application/json, text/plain, */*",
}

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
	user = frappe.session.user
	if not user or user in ("Guest", "Administrator"):
		return

	cache_key = f"kc_role_sync:{user}"
	if frappe.cache().get_value(cache_key):
		return

	frappe.enqueue(
		"kc_role_sync.role_sync._do_sync",
		email=user,
		queue="short",
		timeout=300,
		enqueue_after_commit=True,
	)
	frappe.cache().set_value(cache_key, 1, expires_in_sec=600)


# ── core sync ────────────────────────────────────────────────────────────────

def _do_sync(email: str) -> None:
	_logger.info(f"KC_ROLE_SYNC: _do_sync starting for {email}")
	try:
		clients = _get_keycloak_clients()
		if not clients:
			_logger.info(f"KC_ROLE_SYNC: No Social Login Keys found for site — skipping {email}")
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
				_logger.info(f"KC_ROLE_SYNC: Assigning role '{role}' to {email}")
				added = True

		if added:
			frappe_user.save(ignore_permissions=True)
			frappe.db.commit()
			_logger.info(f"KC_ROLE_SYNC: Roles saved for {email}")
		else:
			_logger.info(f"KC_ROLE_SYNC: No new roles to assign for {email}")

	except Exception as exc:
		_logger.error(f"KC_ROLE_SYNC: Error syncing roles for {email}: {exc}")


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
			_logger.warning(f"KC_ROLE_SYNC: Cannot extract realm from api_endpoint '{api_endpoint}'")
			return []

		token = _get_admin_token(base_url, realm, client_id, client_secret)
		if not token:
			_logger.warning(f"KC_ROLE_SYNC: Could not get admin token for realm '{realm}'")
			return []

		# Locate user in Keycloak by email
		resp = requests.get(
			f"{base_url}/admin/realms/{realm}/users",
			params={"email": email, "exact": "true"},
			headers={**_BROWSER_HEADERS, "Authorization": f"Bearer {token}"},
			timeout=(3, 5),
		)
		users = resp.json() if resp.status_code == 200 else []
		if not users:
			_logger.info(f"KC_ROLE_SYNC: User {email} not found in Keycloak realm '{realm}'")
			return []

		kc_user_id = users[0]["id"]

		# Cache Keycloak sub (user id) → email so the back-channel logout receiver
		# can map Keycloak's logout token (keyed by `sub`) to this user without an
		# extra admin lookup. See kc_role_sync/backchannel.py.
		frappe.cache().set_value(f"kc_sub:{kc_user_id}", email, expires_in_sec=86400)

		# Fetch all role mappings (realm + client-specific)
		resp = requests.get(
			f"{base_url}/admin/realms/{realm}/users/{kc_user_id}/role-mappings",
			headers={**_BROWSER_HEADERS, "Authorization": f"Bearer {token}"},
			timeout=(3, 5),
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

		_logger.info(f"KC_ROLE_SYNC: Found Keycloak roles for {email}: {roles}")
		return roles

	except Exception as exc:
		_logger.error(f"KC_ROLE_SYNC: _get_keycloak_roles failed for {email}: {exc}")
		return []


def _get_admin_token(base_url: str, realm: str, client_id: str, client_secret: str) -> str | None:
	resp = None
	try:
		resp = requests.post(
			f"{base_url}/realms/{realm}/protocol/openid-connect/token",
			data={
				"grant_type": "client_credentials",
				"client_id": client_id,
				"client_secret": client_secret,
			},
			headers=_BROWSER_HEADERS,
			timeout=(3, 5),
		)
		token = resp.json().get("access_token")
		if not token:
			_logger.warning(
				f"KC_ROLE_SYNC: Admin token response had no access_token "
				f"(status={resp.status_code}, body={resp.text[:300]!r})"
			)
		return token
	except Exception as exc:
		if resp is not None:
			_logger.error(
				f"KC_ROLE_SYNC: Admin token request failed: {exc} "
				f"(status={resp.status_code}, body={resp.text[:300]!r})"
			)
		else:
			_logger.error(f"KC_ROLE_SYNC: Admin token request failed before any response: {exc}")
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


# ── Frappe → Keycloak: report this site's own roles ─────────────────────────
#
# The technical-role exclusion list and the opt-in checkbox tracking both live
# in kc_role_sync_settings.py now (single source of truth for "which roles are
# eligible at all").


@frappe.whitelist(allow_guest=True)
def get_client_roles() -> dict:
	"""
	Reports this site's own Role list — the reverse direction of
	sync_on_user_creation/sync_on_session_creation above, which assign
	Keycloak roles TO a user. This is what the portal's "Sync Roles from App"
	pulls so an admin doesn't have to hand-type every role into Keycloak.

	Skips disabled roles and the common Frappe framework roles (see
	kc_role_sync_settings._TECHNICAL_ROLES), and only reports roles this
	site's admin has opted in
	via the "KC Role Sync Settings" checkbox page (kc_role_sync_settings.py).
	New roles default checked, so a client who never opens that page keeps
	today's "sync everything" behaviour.

	Auth: same X-KJI-Secret / kji_push_secret contract as
	module_sync.get_module_structure (set via the site's KJI Portal
	Application.push_secret / `bench set-config kji_push_secret <value>`).
	"""
	_require_secret()

	from kc_role_sync.kc_role_sync.doctype.kc_role_sync_settings.kc_role_sync_settings import (
		get_enabled_roles,
	)

	enabled = get_enabled_roles()
	roles = [{"role_name": name, "role_code": name} for name in sorted(enabled)]
	return {"status": "success", "roles": roles}


@frappe.whitelist(allow_guest=True)
def push_user_roles(email: str, role_names=None) -> dict:
	"""
	Portal pushes a user's desired Role set for THIS app right when an admin approves a
	role add/remove — instead of relying on sync_on_session_creation, which only fires on
	the user's next login and is additive-only (it never removes a role, see _do_sync
	above). This is what actually makes a removal in the portal take effect here without
	waiting for the user to log back in.

	Reconciles both directions (adds missing roles, removes ones no longer desired), but
	ONLY within the roles this site tracks via "KC Role Sync Settings" — the same catalog
	get_client_roles reports from. Anything outside that tracked set (System Manager, a
	role never opted into sync, ...) is never touched, so this can't strip access that
	didn't come from the portal in the first place.

	Auth: same X-KJI-Secret / kji_push_secret contract as get_client_roles.
	"""
	_require_secret()

	if not frappe.db.exists("User", email):
		return {"status": "success", "applied": False, "reason": "user_not_found"}

	if isinstance(role_names, str):
		role_names = json.loads(role_names) if role_names else []
	desired = {r for r in (role_names or []) if r and frappe.db.exists("Role", r)}

	settings = frappe.get_single("KC Role Sync Settings")
	tracked_roles = {row.role for row in settings.roles}

	user = frappe.get_doc("User", email)
	existing = {r.role for r in user.get("roles", [])}

	to_add = desired - existing
	to_remove = (existing & tracked_roles) - desired

	if not to_add and not to_remove:
		return {"status": "success", "applied": False, "added": [], "removed": []}

	for role in sorted(to_add):
		user.append("roles", {"role": role})
	if to_remove:
		user.set("roles", [row for row in user.get("roles", []) if row.role not in to_remove])

	user.save(ignore_permissions=True)
	frappe.db.commit()
	_logger.info(
		f"KC_ROLE_SYNC: Pushed roles for {email} — added {sorted(to_add)}, removed {sorted(to_remove)}"
	)
	return {"status": "success", "applied": True, "added": sorted(to_add), "removed": sorted(to_remove)}


def _require_secret() -> None:
	expected = (frappe.conf.get("kji_push_secret") or "").strip()
	if not expected:
		_logger.error("KC_ROLE_SYNC: kji_push_secret not configured — rejecting")
		frappe.throw("Role sync is not configured on this site.", frappe.AuthenticationError)

	provided = frappe.get_request_header("X-KJI-Secret") or ""
	if provided != expected:
		frappe.throw("Invalid secret.", frappe.AuthenticationError)
