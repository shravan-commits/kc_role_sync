"""
OIDC Back-Channel Logout receiver — runs on every client app (this is the app
clients install).

When a user's Keycloak SSO session is terminated — e.g. CubeHR pushes a
deactivation to the portal, the portal disables the user in Keycloak and kills
their sessions — Keycloak fans out a signed back-channel logout token to every
client that registered a `backchannel.logout.url`. This endpoint validates that
token against Keycloak's JWKS and destroys the user's local Frappe session in
BOTH layers (DB `tabSessions` + Redis `session` cache) so their very next
request is rejected. Deleting only the DB row leaves Redis serving the session.

Register this URL as the client's Keycloak `backchannel.logout.url`:
    https://<client-host>/api/method/kc_role_sync.backchannel.backchannel_logout
and set `backchannel.logout.session.required = true` on the client.

Keycloak base URL, realm, audience (client_id) and JWKS URL are all derived from
the site's Social Login Key — nothing is hardcoded.
"""
from __future__ import annotations

import frappe

NO_PROXY = {"http": "", "https": ""}
_BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


@frappe.whitelist(allow_guest=True)
def backchannel_logout():
    """Receive and process Keycloak's back-channel logout token."""
    if frappe.request.method != "POST":
        frappe.local.response["http_status_code"] = 405
        return {"status": "error", "message": "POST required"}

    logout_token = (
        frappe.request.form.get("logout_token")
        or (frappe.local.form_dict or {}).get("logout_token")
    )
    if not logout_token:
        frappe.logger().error("KC_BACKCHANNEL: no logout_token in request")
        frappe.local.response["http_status_code"] = 400
        return {"status": "error", "message": "missing logout_token"}

    claims = _validate_logout_token(logout_token)
    if not claims:
        frappe.local.response["http_status_code"] = 400
        return {"status": "error", "message": "invalid logout_token"}

    email = _resolve_email(claims)
    if not email:
        frappe.logger().warning("KC_BACKCHANNEL: could not resolve user from logout token")
        return {"status": "ignored", "message": "user not found"}

    killed = _destroy_frappe_sessions(email)
    frappe.logger().info(f"KC_BACKCHANNEL: destroyed {killed} session(s) for {email}")
    return {"status": "success", "user": email, "sessions_killed": killed}


# ── token validation ──────────────────────────────────────────────────────────

def _resolve_kc_config(issuer: str | None):
    """
    Return (base_url, realm, issuer, audiences) from the site's Social Login Key.
    Prefer the client whose issuer matches the token; fall back to the first one.
    """
    from kc_role_sync.role_sync import _get_keycloak_clients, _extract_realm

    clients = _get_keycloak_clients()
    if not clients:
        return None, None, None, []

    audiences = [c.get("client_id") for c in clients if c.get("client_id")]

    for c in clients:
        realm = _extract_realm(c.get("api_endpoint") or "")
        base_url = (c.get("base_url") or "").rstrip("/")
        if realm and base_url and issuer and f"{base_url}/realms/{realm}" == issuer:
            return base_url, realm, issuer, audiences

    c = clients[0]
    realm = _extract_realm(c.get("api_endpoint") or "")
    base_url = (c.get("base_url") or "").rstrip("/")
    return base_url, realm, (issuer or f"{base_url}/realms/{realm}"), audiences


def _validate_logout_token(token: str):
    """
    Validate the back-channel logout token per the OIDC spec:
      1. signature verified against Keycloak's JWKS,
      2. iss matches the realm issuer,
      3. aud contains one of our client_ids,
      4. events contains the backchannel-logout event,
      5. no nonce (that would make it an ID token, not a logout token).
    """
    import requests
    import jwt as pyjwt

    try:
        unverified = pyjwt.decode(token, options={"verify_signature": False})
    except Exception as exc:
        frappe.logger().error(f"KC_BACKCHANNEL: undecodable token: {exc}")
        return None

    base_url, realm, issuer, audiences = _resolve_kc_config(unverified.get("iss"))
    if not base_url or not realm:
        frappe.logger().error("KC_BACKCHANNEL: no usable Social Login Key (base_url/realm)")
        return None

    jwks_url = f"{base_url}/realms/{realm}/protocol/openid-connect/certs"

    # Fetch JWKS through requests so corporate-proxy bypass (NO_PROXY) is honored,
    # then pick the signing key matching the token's kid.
    try:
        jwks = requests.get(jwks_url, proxies=NO_PROXY, timeout=10).json()
        kid = pyjwt.get_unverified_header(token).get("kid")
        jwk_set = pyjwt.PyJWKSet.from_dict(jwks)
        signing_key = next((k.key for k in jwk_set.keys if k.key_id == kid), None)
        if signing_key is None:
            frappe.logger().error(f"KC_BACKCHANNEL: no JWKS key for kid={kid}")
            return None
        claims = pyjwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=audiences or None,
            issuer=issuer,
            options={"require": ["iss", "aud"], "verify_aud": bool(audiences)},
        )
    except Exception as exc:
        frappe.logger().error(f"KC_BACKCHANNEL: token signature/claim validation failed: {exc}")
        return None

    events = claims.get("events") or {}
    if _BACKCHANNEL_EVENT not in events:
        frappe.logger().error("KC_BACKCHANNEL: missing backchannel-logout event claim")
        return None
    if "nonce" in claims:
        frappe.logger().error("KC_BACKCHANNEL: token has a nonce (looks like an ID token) — rejecting")
        return None
    if not claims.get("sub") and not claims.get("sid"):
        frappe.logger().error("KC_BACKCHANNEL: token has neither sub nor sid")
        return None

    return claims


# ── user resolution ───────────────────────────────────────────────────────────

def _resolve_email(claims) -> str | None:
    """Map the logout token to a Frappe user: email claim → sub cache → KC lookup."""
    email = claims.get("email")
    if email and frappe.db.exists("User", email):
        return email

    sub = claims.get("sub")
    if not sub:
        return None

    cached = frappe.cache().get_value(f"kc_sub:{sub}")
    if cached:
        return cached

    email = _lookup_email_by_sub(sub)
    if email:
        frappe.cache().set_value(f"kc_sub:{sub}", email, expires_in_sec=86400)
    return email


def _lookup_email_by_sub(sub: str) -> str | None:
    """Fallback: ask Keycloak (admin API) for the user's email by their id (sub)."""
    import requests
    from frappe.utils.password import get_decrypted_password
    from kc_role_sync.role_sync import (
        _get_keycloak_clients, _get_admin_token, _extract_realm,
    )

    for c in _get_keycloak_clients():
        base_url = (c.get("base_url") or "").rstrip("/")
        realm = _extract_realm(c.get("api_endpoint") or "")
        if not base_url or not realm:
            continue
        try:
            secret = get_decrypted_password("Social Login Key", c["name"], "client_secret")
            token = _get_admin_token(base_url, realm, c["client_id"], secret)
            if not token:
                continue
            r = requests.get(
                f"{base_url}/admin/realms/{realm}/users/{sub}",
                headers={"Authorization": f"Bearer {token}"},
                proxies=NO_PROXY, timeout=10,
            )
            if r.status_code == 200:
                email = r.json().get("email")
                if email:
                    return email
        except Exception as exc:
            frappe.logger().error(f"KC_BACKCHANNEL: sub→email lookup failed: {exc}")
    return None


# ── session destruction (both layers) ─────────────────────────────────────────

def _destroy_frappe_sessions(email: str) -> int:
    """
    Delete the user's sessions from the DB AND purge the Redis session cache.
    `tabSessions` has no `name` PK column, so frappe.qb must be used directly.
    """
    sessions = frappe.qb.DocType("Sessions")
    sids = (
        frappe.qb.from_(sessions)
        .where(sessions.user == email)
        .select(sessions.sid)
    ).run(pluck="sid")

    if not sids:
        return 0

    frappe.qb.from_(sessions).where(sessions.user == email).delete().run()
    frappe.db.commit()

    for sid in sids:
        try:
            frappe.cache().hdel("session", sid)
        except Exception as exc:
            frappe.logger().error(f"KC_BACKCHANNEL: Redis session purge failed for {sid}: {exc}")

    return len(sids)
