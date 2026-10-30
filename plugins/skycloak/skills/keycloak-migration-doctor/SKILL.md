---
name: keycloak-migration-doctor
description: Preflight a Keycloak export, import or migration on a Skycloak-managed cluster against the known blockers, and diagnose a job that already failed by reading the failure reason the API records but the dashboard notice does not show. Use when an export or import fails, a migration stalls, or before moving realm data in or out.
license: Apache-2.0
---

# Keycloak migration doctor

Export and import failures look opaque because the dashboard notice is
generic: "Job has reached the specified backoff limit" is a retry counter,
not a cause. The cause is usually in the job record already, in the
error_message field that skycloak_get_export, skycloak_get_realm_export and
skycloak_get_realm_import all return. Reading it is the single
highest-value step here. If a job has already failed, go straight to
Diagnose; if the move has not run yet, start with Preflight.

## Preflight: before an export, import or migration

1. Pin down the unit with the user: a whole-cluster database dump
   (skycloak_create_export), one realm's archive
   (skycloak_create_realm_export), or a realm import into Skycloak
   (skycloak_create_realm_import). Find the cluster with
   skycloak_list_clusters, then skycloak_get_cluster: it must be
   `available`, and note its Keycloak version, because an archive from a
   newer major does not import into an older target.
2. For an import, call skycloak_list_realms on the target: the import
   refuses a realm-name collision with a 409 rather than overwriting, so a
   taken name is better discovered now than on migration day.
3. Check the known blockers, all taken from support history:
   - **Script-based authorization policies.** Current Keycloak only loads
     JavaScript policies packaged in a deployed scripts JAR, so realms
     whose clients still carry admin-console script policies fail; the
     classic offender is a policy named "Default Policy" that old versions
     auto-created on authorization-enabled clients. No tool lists client
     policies, so use
     skycloak_list_applications to enumerate the clients and have the user
     clear script policies under each client's Authorization > Policies in
     the admin console. The dry run below catches any they miss.
   - **The legacy `/auth` path.** Keycloak dropped the `/auth` URL prefix
     in 17 and Skycloak clusters serve the modern paths, so anything with
     the old prefix hard-coded breaks after the move even though the import
     itself succeeds. Ask now.
   - **partial-export never includes users.** Keycloak's built-in partial
     export excludes users by design. A plan of "partial export, import,
     log in" fails at the login, not the import; users need a full realm
     export.
   - **Feature flags.** If the source relies on a Keycloak feature flag,
     check skycloak_list_cluster_features. A flag absent from that list is
     reserved for the platform operator; escalate rather than promise it.
4. **Dry run now.** The cheapest preflight is running the export today and
   polling it: a failure with error_message in hand this week beats the
   same failure on migration day. Realm archives are always encrypted: ask
   the user for a password, never invent one, and say the same password is
   needed again at import.

## Diagnose: a job that already failed

1. Fetch the job itself, not the notification about it:
   skycloak_list_exports then skycloak_get_export for database exports,
   skycloak_get_realm_export or skycloak_get_realm_import by job ID for
   realm transfers. Realm transfer jobs have no list tool, so if the ID is
   lost, re-run the job: the failure reproduces with a fresh record. Read
   status, progress and above all error_message.
2. Translate error_message into an instruction the user can execute:
   - **Errors naming a policy or script on specific clients:** for each
     client the error names, delete or replace that policy under the
     client's Authorization > Policies, then re-run. Be exactly that
     concrete: name the clients and the policy.
   - **A 409 from skycloak_create_realm_import:** the realm name is taken.
     Whether to rename the import or remove the existing realm is the
     user's decision, not yours.
   - **Decryption or password errors:** wrong archive password. Re-create
     the export rather than guessing.
   - **Version errors on an import:** compare the job's source_version and
     target_version; the target cluster upgrades first (that is the
     keycloak-upgrade-readiness skill), then the import re-runs.
   - **No error_message, or a job parked without progress:** not a
     realm-config problem. Go to the escalation list below.
3. Correlate: skycloak_get_logs for recent errors the job record does not
   carry, and skycloak_query_events with category=admin to see whether
   realm config changed between the last working run and the failing one.
4. **Download and upload URLs are signed.** The signature is in the query
   string, and corporate mail scanners rewrite links and strip it, turning
   a working URL into a 403. Have the user copy URLs from the dashboard or
   this session, never from a forwarded email. Realm export URLs expire 24
   hours after completion, and the upload URL from
   skycloak_create_realm_import_upload_url is for a direct PUT.
5. Re-run the job and poll it to completion before declaring the fix real.

## What this skill cannot fix

Some causes need Skycloak-side action. Recognize them, say so, and escalate
to Skycloak support instead of burning the user's time on retries:

- **Legacy-generation clusters.** The export pipeline does not handle every
  cluster generation, and no tool exposes the generation. A job dying with
  no error_message or with infrastructure errors on a long-lived cluster
  belongs with support, who can run the export manually.
- **Migration-queue state.** A migration dump parked at validation because
  the workspace is not flagged for it is a Skycloak-side switch, invisible
  to every tool here.
- **Operator-reserved feature flags.** Anything absent from
  skycloak_list_cluster_features.

An escalation naming the job ID, the error_message and what was ruled out
is a one-reply ticket; "the export failed" is a ten-thread one.

## Guardrails

- skycloak_create_realm_import creates a realm complete with users and
  credentials: confirm with the user before every call, and pass
  confirm=true only after an explicit yes.
- Treat encryption passwords as secrets: ask when needed, never invent one,
  never repeat one back in a report.
- Delete nothing from this workflow. Removing a policy or a colliding realm
  is the user's action, taken on their say-so.
