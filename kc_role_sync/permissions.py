from __future__ import annotations

import frappe

_RIGHT_FIELDS = [
    "select", "read", "write", "create", "delete",
    "print", "email", "report", "import", "export", "share", "mask",
]


@frappe.whitelist(allow_guest=True)
def apply_permissions(role: str, permissions: list) -> dict:
    """
    Receive a permission matrix push from the central portal and write it into
    Frappe's Custom DocPerm records for the given role.

    Called by the portal's _push_permissions_to_app() with header X-KJI-Secret.
    Each entry in permissions:
      { menu_code, menu_name, can_select, can_read, can_write, can_create,
        can_delete, can_print, can_email, can_report, can_import, can_export,
        can_share, can_mask }
    where values are "yes" | "no" | "" (not-set, treated as no-access). Field
    names map 1:1 onto Custom DocPerm's own right names (can_<right> -> <right>).
    """
    _require_secret()

    if isinstance(permissions, str):
        import json
        permissions = json.loads(permissions)

    if not isinstance(permissions, list):
        frappe.throw("permissions must be a JSON array.")

    if not role or not isinstance(role, str):
        frappe.throw("role is required.")

    if not frappe.db.exists("Role", role):
        frappe.get_doc({
            "doctype": "Role",
            "role_name": role,
            "desk_access": 1,
        }).insert(ignore_permissions=True)
        frappe.db.commit()
        frappe.logger().info(f"KC_PERM_APPLY: created missing Role '{role}' (auto-created on permission push)")

    applied = []
    skipped = []
    errors = []

    for entry in permissions:
        doctype_name = (entry.get("menu_name") or entry.get("menu_code") or "").strip()
        if not doctype_name:
            skipped.append({"reason": "missing menu_name/menu_code", "entry": entry})
            continue

        if not frappe.db.exists("DocType", doctype_name):
            skipped.append({"reason": f"DocType '{doctype_name}' not found", "menu": doctype_name})
            continue

        right_values = {
            right: 1 if str(entry.get(f"can_{right}") or "").strip().lower() == "yes" else 0
            for right in _RIGHT_FIELDS
        }

        try:
            # Remove all existing Custom DocPerm rows for (role, doctype)
            frappe.db.delete(
                "Custom DocPerm",
                {"parent": doctype_name, "role": role},
            )

            # Only write a row if at least one right is granted
            if any(right_values.values()):
                perm = frappe.new_doc("Custom DocPerm")
                perm.parent = doctype_name
                perm.parenttype = "DocType"
                perm.parentfield = "permissions"
                perm.role = role
                perm.permlevel = 0
                for right, value in right_values.items():
                    setattr(perm, right, value)
                perm.insert(ignore_permissions=True)

            applied.append(doctype_name)

        except Exception as exc:
            errors.append({"doctype": doctype_name, "error": str(exc)})
            frappe.logger().error(
                f"KC_PERM_APPLY: failed to apply perm for role={role} doctype={doctype_name}: {exc}"
            )

    if applied:
        frappe.clear_cache()

    frappe.db.commit()
    frappe.logger().info(
        f"KC_PERM_APPLY: role={role} applied={len(applied)} skipped={len(skipped)} errors={len(errors)}"
    )

    return {
        "status": "success" if not errors else "partial",
        "role": role,
        "applied": len(applied),
        "applied_list": applied,
        "skipped": skipped,
        "errors": errors,
    }


def _require_secret() -> None:
    expected = (frappe.conf.get("kji_push_secret") or "").strip()
    if not expected:
        frappe.logger().error("KC_PERM_APPLY: kji_push_secret not configured — rejecting")
        frappe.throw("Permission sync is not configured on this site.", frappe.AuthenticationError)
    provided = frappe.get_request_header("X-KJI-Secret") or ""
    if provided != expected:
        frappe.throw("Invalid secret.", frappe.AuthenticationError)
