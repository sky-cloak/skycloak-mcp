---
name: keycloak-upgrade-readiness
description: Assess whether Skycloak-managed Keycloak clusters are ready to upgrade, work out what the new version breaks, and sequence the rollout across environments with a tested rollback plan. Use when asked to upgrade Keycloak, review version drift, or plan an upgrade rollout.
license: Apache-2.0
---

# Keycloak upgrade readiness

Upgrading Keycloak is a database migration wearing a version number. The
migrations run at startup and are one-way: once a cluster has started on the
new version, the only road back is restoring an export taken before the
upgrade. Plan accordingly, and never treat this as "bump the version field".

## Phase 1: assess the estate

1. Call skycloak_list_clusters and record, per cluster: type, current version,
   status, and whether auto_upgrade_enabled is set. A cluster that is not
   `available` is not a candidate for anything until it is.
2. For each cluster type in use, call skycloak_list_cluster_versions to learn
   the newest version offered. Rank clusters by how far behind they are.
3. For each cluster that is behind, call skycloak_get_cluster_upgrade_path.
   The path is the authority on sequencing: follow its steps in order and do
   not invent shortcuts across majors, even when the API would accept the
   target version directly. Keycloak ships roughly three majors a year and
   only the newest line receives fixes, so "furthest behind" is also "most
   exposed".
4. Call skycloak_list_cluster_upgrades for recent history. A previously
   failed or cancelled upgrade on the same cluster is a red flag to explain
   before retrying, not to retry past.

## Phase 2: what the new version breaks

Work through these for every step in the path, using the release notes for
that version as the checklist. The usual suspects, most breakage first:

- **Extensions.** Keycloak's server SPIs are not stable across majors: a
  provider compiled against one major can fail to deploy on the next. Call
  skycloak_list_cluster_extensions for each cluster, then
  skycloak_list_extensions to see whether newer builds of those extensions
  exist. Upgrade the extension first with skycloak_upgrade_extension where a
  compatible build is available; where none is, the cluster upgrade waits.
- **Custom themes.** FreeMarker templates and the login form structure change
  between majors. Call skycloak_list_themes and note which realms carry a
  custom theme; those realms need a visual check of the login, registration
  and email templates after each upgrade step.
- **Deprecated surfaces.** Very old estates may still have clients using
  removed adapter endpoints or the legacy `/auth` path prefix. Flag them now;
  they fail loudly after the upgrade, not before.

## Phase 3: sequence the rollout

Order environments dev, then staging, then production. If the environment
split is not obvious from cluster names, ask the user rather than guessing.
For each environment, in order:

1. **Export first.** Call skycloak_create_export, then poll
   skycloak_get_export until status is `completed`. This export is the
   rollback plan; an upgrade without one is a bet, and you should say so.
2. **Window it.** For production, check skycloak_get_cluster_maintenance_window
   and, if the user wants the upgrade inside a specific window, set it with
   skycloak_set_cluster_maintenance_window. Confirm the window with the user
   before relying on it.
3. **Trigger one step.** Call skycloak_update_cluster with the next version
   from the upgrade path, never the final target in one jump when the path
   has intermediate steps. The upgrade is asynchronous: poll
   skycloak_get_cluster until status returns to `available`.
4. **Verify before the next step.** Pull skycloak_get_logs for startup errors,
   then skycloak_query_events to confirm real logins are succeeding on the
   new version. If any realm carries a custom theme, have a human eyeball the
   login page. Only then take the next step in the path, or move to the next
   environment.
5. **Soak.** Let staging run for a period the user is comfortable with before
   touching production. A migration problem that takes two days to surface is
   only cheap in staging.

If an upgrade is queued but has not started and the plan changes, call
skycloak_cancel_cluster_upgrade. Once a cluster has come up on the new
version, cancel is no longer the tool; restore from the export is.

## Guardrails

- Stop the whole rollout on the first failure. Do not continue to production
  because "staging mostly worked".
- Confirm with the user before every skycloak_update_cluster call: name the
  cluster, the current version, and the exact version you are about to move
  it to.
- This workflow never deletes anything. If asked to also clean up old
  clusters or exports as part of an upgrade, treat that as a separate task
  with its own confirmation.
