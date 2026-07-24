from __future__ import annotations

import frappe
from frappe.model.document import Document

# Same framework-role exclusion list as role_sync.get_client_roles — these are
# never meaningful as a Keycloak client role, so they're never offered as a
# checkbox either.
_TECHNICAL_ROLES = frozenset([
	"Guest",
	"All",
	"Administrator",
	"Desk User",
])


class KCRoleSyncSettings(Document):
	def onload(self):
		# Keeps the checkbox grid current every time an admin opens this page,
		# so newly created roles (custom app installs, new business roles, ...)
		# show up without needing a separate reconcile step.
		if reconcile_synced_roles():
			self.reload()


def reconcile_synced_roles() -> bool:
	"""
	Adds a row (default checked, to preserve today's "sync everything" behaviour
	for roles that already existed before this feature) for any Role not yet
	tracked, and drops rows for roles that were deleted or disabled since.
	Returns True if the settings doc changed.
	"""
	settings = frappe.get_single("KC Role Sync Settings")

	live_roles = set(
		frappe.get_all(
			"Role",
			filters={"disabled": 0, "name": ["not in", list(_TECHNICAL_ROLES)]},
			pluck="name",
		)
	)
	tracked_roles = {row.role for row in settings.roles}

	changed = False

	for role in sorted(live_roles - tracked_roles):
		settings.append("roles", {"role": role, "sync_enabled": 1})
		changed = True

	for row in list(settings.roles):
		if row.role not in live_roles:
			settings.remove(row)
			changed = True

	if changed:
		settings.save(ignore_permissions=True)
		frappe.db.commit()

	return changed


def get_enabled_roles() -> set[str]:
	"""Role names currently opted in for sync, reconciling first so a role
	created moments ago is never missed."""
	reconcile_synced_roles()
	settings = frappe.get_single("KC Role Sync Settings")
	return {row.role for row in settings.roles if row.sync_enabled}
