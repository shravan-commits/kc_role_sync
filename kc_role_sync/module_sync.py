from __future__ import annotations

import frappe

# Apps whose modules are "common Frappe" rather than client-built — never
# reported to the portal. Anything else installed on the site is assumed to
# be the client's own custom app(s).
_CORE_APPS = frozenset([
    "frappe", "erpnext", "hrms", "payments", "payroll", "india_compliance",
    "kc_role_sync",
])


@frappe.whitelist(allow_guest=True)
def get_module_structure() -> dict:
    """
    Reports this site's custom modules and the DocTypes (tables) under each.

    Shape matches what keycloak_integration.api.push_modules / sync_modules
    already expect: {"status", "modules": [{"module_name", "module_code",
    "doctypes": [{"doctype_name", "is_child_table"}, ...]}]}.

    Set this as the `module_sync_url` on the site's KJI Portal Application
    record (e.g. /api/method/kc_role_sync.module_sync.get_module_structure)
    so the portal's "Sync Now" pulls from here — no per-client code needed.

    Auth: the portal sends the app's KJI Portal Application.push_secret as the
    X-KJI-Secret header. The same value must be set in this site's
    site_config.json as "kji_push_secret" (bench set-config kji_push_secret
    <value>). Fails closed — no configured secret means every request is
    rejected, not allowed through.
    """
    _require_secret()

    custom_apps = [a for a in frappe.get_installed_apps() if a not in _CORE_APPS]
    if not custom_apps:
        return {"status": "success", "modules": []}

    module_defs = frappe.get_all(
        "Module Def",
        filters={"app_name": ["in", custom_apps]},
        fields=["name", "app_name"],
    )

    modules: list[dict] = []
    for mod in module_defs:
        doctypes = frappe.get_all(
            "DocType",
            filters={"module": mod["name"]},
            fields=["name", "istable"],
            order_by="name asc",
        )
        modules.append({
            "module_name": mod["name"],
            "module_code": mod["name"].upper().replace(" ", "-"),
            "doctypes": [
                {"doctype_name": dt["name"], "is_child_table": dt["istable"]}
                for dt in doctypes
            ],
        })

    return {"status": "success", "modules": modules}


def _require_secret() -> None:
    expected = (frappe.conf.get("kji_push_secret") or "").strip()
    if not expected:
        frappe.logger().error("KC_MODULE_SYNC: kji_push_secret not configured — rejecting")
        frappe.throw("Module sync is not configured on this site.", frappe.AuthenticationError)

    provided = frappe.get_request_header("X-KJI-Secret") or ""
    if provided != expected:
        frappe.throw("Invalid secret.", frappe.AuthenticationError)
