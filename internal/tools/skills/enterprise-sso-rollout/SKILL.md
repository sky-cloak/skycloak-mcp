---
name: enterprise-sso-rollout
description: Wire an enterprise identity provider (Entra ID, Okta, Google, or any OIDC issuer) into a Keycloak realm end to end, including the upstream app registration, broker configuration, connection testing, and verification against real login events. Use when asked to set up SSO, connect an IdP, or onboard a customer's identity provider.
license: Apache-2.0
---

# Enterprise SSO rollout

Brokering an external IdP into Keycloak fails in predictable places: the
redirect URI, the issuer, the email claim, and the alias. This workflow front
loads all four so the first real login works.

## Step 1: establish the target

1. Find the realm: skycloak_list_clusters, then skycloak_list_realms, then
   skycloak_get_realm to confirm it is enabled. If the realm name exists in
   more than one cluster, ask which one is meant.
2. Call skycloak_list_identity_provider_templates and pick the template
   matching the upstream (for example microsoft-entra, google, okta). A
   template pre-fills endpoints and scopes; prefer it over a raw OIDC setup
   when one matches.
3. Check what already exists with skycloak_list_identity_providers. A
   half-configured provider from an earlier attempt should be finished or
   removed, not duplicated under a second alias.

## Step 2: validate the issuer before creating anything

Ask the user for the upstream issuer URL and run skycloak_discover_oidc on
it. This catches the cheap failures before they are wired into a realm:

- **Trailing slash and casing.** The `issuer` value inside the discovery
  document must match what the tokens will carry, byte for byte. If discovery
  succeeds but the issuer differs from the URL the user gave, use the
  document's value.
- **Entra ID:** use the tenant-specific endpoint
  (`login.microsoftonline.com/<tenant-id>/v2.0`), not `/common`. The common
  endpoint issues tokens whose issuer varies per tenant, which fails
  validation at the broker.
- **Okta:** confirm whether the org authorization server or a custom one is
  intended; they have different issuers and different token contents.

## Step 3: the upstream app registration

The customer's IdP admin must register Keycloak as a client. Hand them the
broker callback URL, which is
`https://<keycloak-host>/realms/<realm>/broker/<alias>/endpoint`:

- Choose the alias now and deliberately. It is case sensitive, it appears in
  every URL, and changing it later means re-registering the callback at the
  upstream and breaking existing federated links. Short, lowercase, stable.
- If the realm is served on a custom domain, check skycloak_list_domains and
  skycloak_get_domain for the verified hostname and register the callback on
  that host. A callback registered against the default hostname stops working
  the day traffic moves to the custom domain.
- The upstream registration must grant the `openid`, `email` and `profile`
  scopes. A missing email claim is the most common cause of first logins
  stalling on an update-profile form or failing account linking outright.

## Step 4: create and test

1. Ask the user for the client_id and client_secret from the upstream
   registration. Never invent or reuse credentials.
2. Call skycloak_create_identity_provider with the validated endpoints, the
   chosen alias, and those credentials.
3. Call skycloak_test_identity_provider. If it fails, map the error before
   touching anything else:
   - `redirect_uri_mismatch`: the upstream registration does not carry the
     broker callback exactly. It is a string match; compare character by
     character, including scheme and trailing path.
   - `unauthorized_client` or `invalid_client`: wrong or expired secret.
     Entra ID secrets expire by default; ask when it was created.
   - Issuer or discovery errors: back to Step 2, the issuer is wrong.
4. Then verify with a real browser login, not just the connectivity test, and
   read the outcome with skycloak_query_events: a successful brokered login
   appears as a login event carrying the provider's alias, and first-time
   users produce a first-broker-login flow. An `email` collision here means a
   local account already exists with the same address; decide the linking
   policy with the user rather than deleting either account.

## Step 5: finish deliberately

- Confirm the provider state with skycloak_get_identity_provider and set a
  human display name with skycloak_update_identity_provider so the login page
  button reads "Sign in with Acme", not the alias.
- Decide with the user what happens to local password logins for this realm:
  leaving them enabled is the safe default during rollout; disabling them is
  a separate, explicit step after SSO has proven itself.
- If the rollout is abandoned, remove the provider with
  skycloak_delete_identity_provider (confirm first) and tell the user that
  users who already signed in through it keep their accounts but lose that
  sign-in path.
