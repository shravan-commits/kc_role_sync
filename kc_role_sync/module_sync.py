from __future__ import annotations

import frappe

# Apps whose modules are "common Frappe" rather than client-built — never
# reported to the portal. Anything else installed on the site is assumed to
# be the client's own custom app(s).
_CORE_APPS = frozenset([
    "frappe", "erpnext", "hrms", "payments", "payroll", "india_compliance",
    "kc_role_sync",
])

# ERPNext/HRMS ship as "core" apps above, so their DocTypes are normally never
# reported. These are the masters client admins actually need to grant menu
# permissions on — reported under a synthetic "ERPNext Masters" module.
# Edit this list to add/remove doctypes as client needs change.
_ERPNEXT_IMPORTANT_DOCTYPES = [
    "Employee", "Department", "Designation", "Leave Application", "Leave Type",
    "Attendance", "Holiday List", "Salary Slip", "Salary Structure", "Expense Claim",
    "Customer", "Supplier", "Item", "Sales Order", "Purchase Order",
    "Sales Invoice", "Purchase Invoice", "Payment Entry", "Journal Entry",
    "Warehouse", "Company", "Cost Center", "Project", "Task",
]


@frappe.whitelist(allow_guest=True)
def get_module_structure() -> dict:
    """
    Reports this site's custom modules and the DocTypes (tables) under each.

    Shape matches what keycloak_integration.api.push_modules / sync_modules
    already expect: {"status", "modules": [{"module_name", "module_code",
    "doctypes": [{"doctype_name", "is_child_table"}, ...],
    "menus": [{"menu_name", "menu_code"}, ...]}]}.

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
    modules: list[dict] = []
    # Every doctype name already placed in `modules` above — the portal keys
    # KJI Application Module DocType by app + doctype_name only (not module), so
    # the same doctype_name reported twice across two module blocks in one sync
    # collides on that primary key. Anything a custom app already reports under
    # its own (correct) module must never also show up under the synthetic
    # "ERPNext Masters" block below, even if it's a link-field dependency of one
    # of the curated masters.
    reported_names: set[str] = set()

    if custom_apps:
        module_defs = frappe.get_all(
            "Module Def",
            filters={"app_name": ["in", custom_apps]},
            fields=["name", "app_name"],
        )
        for mod in module_defs:
            doctypes = frappe.get_all(
                "DocType",
                filters={"module": mod["name"]},
                fields=["name", "istable"],
                order_by="name asc",
            )
            # Non-child doctypes are directly navigable screens — they are the
            # "menus" the portal uses for permission matrix rows.
            menus = [
                {
                    "menu_name": dt["name"],
                    "menu_code": dt["name"].upper().replace(" ", "-"),
                }
                for dt in doctypes
                if not dt["istable"]
            ]
            modules.append({
                "module_name": mod["name"],
                "module_code": mod["name"].upper().replace(" ", "-"),
                "doctypes": [
                    {"doctype_name": dt["name"], "is_child_table": dt["istable"]}
                    for dt in doctypes
                ],
                "menus": menus,
            })
            reported_names.update(dt["name"] for dt in doctypes)

    if "erpnext" in frappe.get_installed_apps():
        dependency_names = _resolve_link_dependencies(_ERPNEXT_IMPORTANT_DOCTYPES) - reported_names
        all_names = sorted((set(_ERPNEXT_IMPORTANT_DOCTYPES) | dependency_names) - reported_names)
        erpnext_doctypes = frappe.get_all(
            "DocType",
            filters={"name": ["in", all_names]},
            fields=["name", "istable"],
            order_by="name asc",
        )
        if erpnext_doctypes:
            modules.append({
                "module_name": "ERPNext Masters",
                "module_code": "ERPNEXT-MASTERS",
                "doctypes": [
                    {
                        "doctype_name": dt["name"],
                        "is_child_table": dt["istable"],
                        "is_dependency": dt["name"] in dependency_names,
                    }
                    for dt in erpnext_doctypes
                ],
                "menus": [
                    {
                        "menu_name": dt["name"],
                        "menu_code": dt["name"].upper().replace(" ", "-"),
                        "is_dependency": dt["name"] in dependency_names,
                    }
                    for dt in erpnext_doctypes
                    if not dt["istable"]
                ],
            })

    return {"status": "success", "modules": modules}


def _resolve_link_dependencies(doctype_names: list[str]) -> set[str]:
    """
    One level of Link-field targets for each doctype in doctype_names, so a role
    that can use (e.g.) Sales Invoice also gets matrix rows for what that form
    actually needs to populate its own link-field dropdowns (Price List, Payment
    Terms Template, UOM, Territory, ...) — those were previously invisible in the
    permission matrix, so a role could be granted "Sales Invoice" and still hit
    empty/unselectable dropdowns for masters it depends on.

    Deliberately one level only, not recursive: recursing into each dependency's
    own links would pull in a large, unreviewable slice of ERPNext's doctype
    graph (e.g. Item -> Item Group -> ... ) and defeat the point of a curated,
    admin-reviewable list. Child tables are excluded — those are governed by the
    parent doctype's own permission, not their own, per Frappe's permission model.
    Frappe's own Core module (User, Role, DocType, Language, ...) is excluded
    too — those are System Manager territory, not an app-role permission the
    portal's matrix is meant to hand out.
    """
    resolved: set[str] = set()
    seen_source = set(doctype_names)
    for doctype_name in doctype_names:
        if not frappe.db.exists("DocType", doctype_name):
            continue
        try:
            meta = frappe.get_meta(doctype_name)
        except Exception:
            continue
        for field in meta.get_link_fields():
            target = field.options
            if not target or target in seen_source or target in resolved:
                continue
            if not frappe.db.exists("DocType", target):
                continue
            target_meta = frappe.get_meta(target)
            if target_meta.istable or target_meta.module == "Core":
                continue
            resolved.add(target)
    return resolved


def _require_secret() -> None:
    expected = (frappe.conf.get("kji_push_secret") or "").strip()
    if not expected:
        frappe.logger().error("KC_MODULE_SYNC: kji_push_secret not configured — rejecting")
        frappe.throw("Module sync is not configured on this site.", frappe.AuthenticationError)

    provided = frappe.get_request_header("X-KJI-Secret") or ""
    if provided != expected:
        frappe.throw("Invalid secret.", frappe.AuthenticationError)
