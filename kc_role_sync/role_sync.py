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
	and Frappe creates their account. Assigns Keycloak roles in the
	background: the Admin API call this depends on has been observed to take
	80+ seconds on this network (proxy latency, not a hard failure), far too
	long to block the user's actual login response on — so this is enqueued
	the same way sync_on_session_creation already handles it, instead of
	calling _do_sync inline.
	"""
	frappe.enqueue(
		"kc_role_sync.role_sync._do_sync",
		email=doc.name,
		queue="short",
		timeout=300,
		enqueue_after_commit=True,
	)
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


# ── fast path: roles straight from the login token ──────────────────────────

@frappe.whitelist(allow_guest=True)
def login_via_keycloak_fast(code: str, state: str):
	"""
	Overrides frappe.integrations.oauth2_logins.login_via_keycloak (wired up
	via override_whitelisted_methods in hooks.py) so Keycloak roles are
	assigned on the spot at login, instead of only via the separate,
	slow/flaky Admin API round-trip in _do_sync.

	Does the exact same OAuth exchange Frappe core's own login_via_keycloak
	does — reusing core's own get_oauth2_flow/get_redirect_uri/
	login_oauth_user helpers directly, so state validation, user creation,
	and session login behave identically to core's implementation. The only
	addition: core computes the raw access token during this exchange and
	then discards it after fetching userinfo — here it's kept and decoded
	for this client's `resource_access` roles (same claim the central
	portal's own establish_session reads), applied via the same
	_apply_roles() the slow path uses.

	sync_on_session_creation still fires on every login as a fallback
	(rate-limited to once per 10 minutes via the shared cache key below),
	in case a role changed in Keycloak after this token was minted, or this
	fast path fails for any reason.
	"""
	from frappe.utils.oauth import get_email, get_oauth2_flow, get_oauth2_providers, get_redirect_uri, login_oauth_user

	provider = "keycloak"

	try:
		flow = get_oauth2_flow(provider)
		session = flow.get_auth_session(
			data={
				"code": code,
				"redirect_uri": get_redirect_uri(provider),
				"grant_type": "authorization_code",
			},
			decoder=lambda b: json.loads(bytes(b).decode("utf-8")),
		)
	except Exception as exc:
		# Don't leave the user stuck if our own exchange attempt fails for
		# any reason — fall back to core's real implementation.
		_logger.error(f"KC_ROLE_SYNC: fast-path token exchange failed, falling back to core: {exc}")
		import frappe.integrations.oauth2_logins as _core_oauth2_logins
		return _core_oauth2_logins.login_via_keycloak(code, state)

	access_token = getattr(session, "access_token", None)

	oauth2_providers = get_oauth2_providers()
	api_endpoint = oauth2_providers[provider].get("api_endpoint")
	api_endpoint_args = oauth2_providers[provider].get("api_endpoint_args")
	info = session.get(api_endpoint, params=api_endpoint_args).json()

	if not (info.get("email_verified") or get_email(info)):
		frappe.throw(f"Email not verified with {provider.title()}")

	candidate_roles: list[str] = []
	if access_token:
		try:
			import jwt as pyjwt
			claims = pyjwt.decode(access_token, options={"verify_signature": False})
			resource_access = claims.get("resource_access", {})
			candidate_roles = resource_access.get(flow.client_id, {}).get("roles", [])
		except Exception as exc:
			_logger.warning(f"KC_ROLE_SYNC: fast-path JWT decode failed: {exc}")

	# Does state validation, user find-or-create, and session login exactly
	# like core's own login_via_keycloak — this is core's real function,
	# just called directly instead of via the whitelisted wrapper.
	login_oauth_user(info, provider=provider, state=state)

	user = frappe.session.user
	if user and user != "Guest":
		# Login has already succeeded at this point (session established) —
		# a failure in role assignment must not turn into a broken response
		# for what is otherwise a successful login.
		try:
			added: list[str] = []
			if candidate_roles:
				added = _apply_roles(user, candidate_roles)
				if added:
					_logger.info(f"KC_ROLE_SYNC: fast-path assigned roles for {user}: {added}")
				else:
					_logger.info(f"KC_ROLE_SYNC: fast-path found no new roles to assign for {user}")
			else:
				_logger.info(f"KC_ROLE_SYNC: fast-path got no resource_access roles for {user}")
			# Same dedupe key sync_on_user_creation/sync_on_session_creation
			# use, so the fallback background sync doesn't immediately redo
			# this — only stamped on success, so a failure here still lets
			# the background fallback have a go.
			frappe.cache().set_value(f"kc_role_sync:{user}", 1, expires_in_sec=600)

			if added:
				# login_oauth_user() (above) already decided and set the
				# post-login redirect via redirect_post_login(), but it did
				# so BEFORE these roles existed — for a brand-new user that
				# means it saw someone with no roles yet and sent them to
				# the website/home page instead of the desk. Redo that
				# decision now that the user's roles are actually current,
				# so a first-ever login lands in the same place a second
				# login would (instead of needing a second attempt).
				from frappe.utils.oauth import redirect_post_login
				desk_user = frappe.db.get_value("User", user, "user_type") == "System User"
				redirect_post_login(desk_user=desk_user, provider=provider)
		except Exception as exc:
			_logger.error(f"KC_ROLE_SYNC: fast-path role assignment failed for {user}: {exc}")


# ── core sync ────────────────────────────────────────────────────────────────

def _apply_roles(email: str, candidate_roles: list[str]) -> list[str]:
	"""
	Assigns whichever of candidate_roles exist as Frappe Roles and aren't
	already on the user. Shared by both the slow Admin-API path (_do_sync)
	and the fast JWT-decode path (login_via_keycloak_fast) so role
	application logic only lives in one place.
	"""
	frappe_user = frappe.get_doc("User", email)
	existing_roles = {r.role for r in frappe_user.get("roles", [])}

	added: list[str] = []
	for role in set(candidate_roles):
		if not _is_internal(role) and frappe.db.exists("Role", role) and role not in existing_roles:
			frappe_user.append("roles", {"role": role})
			added.append(role)

	if added:
		frappe_user.save(ignore_permissions=True)
		frappe.db.commit()

	return added


def _do_sync(email: str) -> None:
	_logger.info(f"KC_ROLE_SYNC: _do_sync starting for {email}")
	try:
		clients = _get_keycloak_clients()
		if not clients:
			_logger.info(f"KC_ROLE_SYNC: No Social Login Keys found for site — skipping {email}")
			return

		new_roles: list[str] = []
		for client in clients:
			new_roles.extend(_get_keycloak_roles(client, email))

		added = _apply_roles(email, new_roles)
		if added:
			_logger.info(f"KC_ROLE_SYNC: Roles saved for {email}: {added}")
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
			timeout=(10, 40),
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
			timeout=(10, 40),
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
	# Observed: this specific call (client_credentials grant, through this
	# deployment's proxy) can take 80+ seconds to complete even when it does
	# succeed — genuinely slow/intermittently flaky, not a hard failure. A
	# couple of bounded retries handles that far better than one long wait,
	# and since the caller now runs this in a background job (see
	# sync_on_user_creation), the extra time has no user-facing cost.
	for attempt in range(1, 3):
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
				timeout=(10, 40),
			)
			token = resp.json().get("access_token")
			if not token:
				_logger.warning(
					f"KC_ROLE_SYNC: Admin token response had no access_token "
					f"(attempt={attempt}, status={resp.status_code}, body={resp.text[:300]!r})"
				)
			return token
		except Exception as exc:
			if resp is not None:
				log = f"KC_ROLE_SYNC: Admin token attempt {attempt} failed: {exc} (status={resp.status_code}, body={resp.text[:300]!r})"
			else:
				log = f"KC_ROLE_SYNC: Admin token attempt {attempt} failed before any response: {exc}"
			if attempt < 2:
				_logger.warning(log)
			else:
				_logger.error(log)

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


@frappe.whitelist(allow_guest=True)
def get_recent_logs(lines: int = 200) -> dict:
	"""
	Remote-readable tail of this site's own kc_role_sync.log — lets the
	central portal pull diagnostic output directly over HTTPS instead of
	needing someone with server access to manually copy/paste it every time.

	Auth: same X-KJI-Secret / kji_push_secret contract as get_client_roles.
	"""
	_require_secret()

	import os

	try:
		n = max(1, min(int(lines), 2000))
	except (TypeError, ValueError):
		n = 200

	site_log = frappe.utils.get_site_path("logs", "kc_role_sync.log")
	bench_log = os.path.join(frappe.utils.get_bench_path(), "logs", "kc_role_sync.log")
	log_path = site_log if os.path.exists(site_log) else (bench_log if os.path.exists(bench_log) else None)

	if not log_path:
		return {"status": "not_found", "checked": [site_log, bench_log]}

	with open(log_path, encoding="utf-8", errors="replace") as f:
		content = f.readlines()

	return {"status": "success", "path": log_path, "lines": content[-n:]}
