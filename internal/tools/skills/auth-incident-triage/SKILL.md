---
name: auth-incident-triage
description: Triage a live authentication incident on a Skycloak-managed Keycloak cluster, separating platform outages from attacks and from configuration changes, using events, WAF logs and cluster health. Read-only. Use when users cannot log in, login failures spike, or SSO suddenly breaks.
license: Apache-2.0
---

# Authentication incident triage

"Users cannot log in" has three root-cause families: the platform is
unhealthy, someone is attacking, or someone changed something. The fastest
triage decides between those families first and only then digs. This
workflow is strictly read-only: gather, correlate, conclude, recommend. Take
no corrective action from inside it.

## Step 1: scope the blast radius

Before any tool call, pin down from the reporter: all users or a subset? One
application or all of them? Interactive logins, token refreshes, or both?
Since exactly when? The answers pick the branch below, and "since exactly
when" is the single most valuable fact you can get.

## Step 2: rule the platform in or out

1. skycloak_get_cluster: if status is not `available`, this is a platform
   incident. Note the status, stop configuration hunting, and escalate to
   Skycloak support; nothing in realm config fixes an unavailable cluster.
2. skycloak_get_logs: restarts, database errors, or out-of-memory kills near
   the onset time mean platform first, config second.
3. skycloak_get_cluster_insights with type=authentication: a cliff in the
   success rate at a precise timestamp corroborates the reported onset and
   often dates it better than the reporter can.

## Step 3: read the failures themselves

Call skycloak_query_events with category=user for the affected realm and a
generous limit, then group failures by error, ip_address, username and
client_id. The shape of the grouping is the diagnosis:

- **One IP, many usernames:** password spraying. Check
  skycloak_get_security_logs to see whether the WAF is already blocking the
  source; if the noise is getting through, that is the finding.
- **Many IPs, one or few usernames:** credential stuffing against specific
  accounts. The account owners need a reset; the edge needs rate limiting.
- **One client_id failing with invalid client credentials:** a service is
  using a rotated or expired secret. This is a deployment problem, not an
  attack. skycloak_list_application_sessions shows how much live traffic the
  client still carries.
- **A spike of user-not-found:** usually an identity-provider or username
  format change upstream, not users forgetting who they are.
- **Errors naming an identity provider:** move to Step 5.

## Step 4: correlate with change

Call skycloak_query_events with category=admin around the onset time. Most
incidents that are not attacks are changes: an authentication flow edited, a
provider disabled, a client secret rotated, required actions added. If an
admin event lands minutes before the first failure, you have the story;
report who, what and when, and recommend reverting through a human decision,
not automatically.

## Step 5: SSO-specific checks

When failures involve brokered logins:

1. skycloak_list_identity_providers, then skycloak_get_identity_provider for
   the affected alias: is it enabled, and did its config change (Step 4 shows
   by whom)?
2. If the provider config is untouched and errors are timeouts or upstream
   rejections, the upstream IdP is the suspect; check its status page before
   touching Keycloak.
3. For OTP-by-email or password-reset flows failing silently, confirm the
   realm has SMTP configured at all with skycloak_get_smtp. Do not send test
   mail from this workflow; absence or obvious misconfiguration is enough to
   report.

## Step 6: the edge

1. skycloak_get_security_logs: WAF blocks near onset, and whether legitimate
   traffic is being caught in them.
2. skycloak_get_cluster_security: recently tightened settings, CAPTCHA
   enforcement, or IP rules that coincide with the incident window.
3. If login pages are served on a custom domain, skycloak_list_domains and
   skycloak_get_domain: an expired or failed SSL state or a DNS change breaks
   "login" for every user while the cluster itself is perfectly healthy.

## Step 7: report

Deliver: the blast radius, a timeline anchored on the onset, which family
the incident falls into (platform, attack, change), the evidence for that
call, and the recommended next actions with their owners. Name what you
ruled out and how. If the family is "platform", say explicitly that the fix
is with Skycloak support, and that everything else you found is secondary.
