# kde-auth — honnêteté discovery OIDC / id_token

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

**Priorité :** cassé / menteur. Le document `/.well-known/openid-configuration` annonce `id_token_signing_alg_values_supported` (RS256) alors que la réponse `/token` **n’émet jamais** d’`id_token`. Les claims d’identité (`email`, `email_verified`, `role`) vivent aujourd’hui dans l’**access token**.

## Produit

L’issuer doit être **honnête** envers les clients qui lisent le discovery : soit il se comporte en fournisseur OIDC Core minimal (émet un `id_token`), soit le discovery ne prétend plus supporter les ID Tokens.

Deux options produit (en choisir **une** à la validation de cette spec, avant le plan d’implémentation) :

| Option | Effet |
|--------|--------|
| **A — Honest discovery** | Retirer du discovery tout signal d’ID Token ; documenter que l’identité est dans l’access JWT + `/userinfo`. Suffisant tant que tous les clients sont first-party et déjà adaptés. |
| **B — ID Token réel** | Émettre `id_token` (RS256) sur `/token` quand `openid` est dans le scope ; echo `nonce` si fourni à `/authorize` ; claims minimales `iss`, `sub`, `aud`, `exp`, `iat` (+ email si scope `email`). |

**Recommandation d’audit (défaut proposé) :** option **A** d’abord (correctif rapide, truthful), puis option **B** en feature ultérieure si un client tiers / standard OIDC le exige. Si on choisit **B** tout de suite, cette spec devient la tranche « émettre id_token » et A disparaît.

## Processus (si option A)

1. Mettre à jour le metadata discovery pour ne plus annoncer le support ID Token.
2. README / docs internes : access token + userinfo = profil.
3. Aucun changement de réponse `/token` pour les clients existants.

## Processus (si option B)

1. `/authorize` accepte un paramètre optionnel `nonce` et le stocke sur le code d’autorisation.
2. `/token` (authorization_code et, si pertinent, refresh selon règles OIDC retenues) inclut `id_token` signé RS256.
3. Discovery conserve / précise les champs ID Token de façon exacte (`claims_supported` minimal si on les ajoute).
4. Les clients first-party peuvent ignorer `id_token` et continuer à lire l’access token.

## Règles

- Ne jamais annoncer une capacité absente.
- `openid` reste obligatoire dans le scope (déjà le cas).
- Pas de `prompt`, `max_age`, `auth_time` dans la première tranche ID Token (hors scope B v1).
- L’access token peut continuer à porter email/role (compat first-party) ; ce n’est pas un substitut documenté d’`id_token` si B est choisi.

## API (issuer)

| Surface | Option A | Option B |
|---------|----------|----------|
| `GET /.well-known/openid-configuration` | sans `id_token_signing_alg_values_supported` (et sans autres champs ID Token inventés) | aligné sur ce qui est vraiment émis |
| `POST /token` | inchangé | + `id_token` string JWT |
| `GET /authorize` | inchangé | + `nonce` optionnel mémorisé |

## Clients

- Portclos / Instacrane : aucun changement obligatoire si A ; si B, peuvent ignorer `id_token`.
- Tout client strict OIDC : A les force à userinfo/access ; B les débloque.

## Hors scope (cette version)

- `prompt=login` / `max_age` / `auth_time`.
- Rotation de clés JWKS.
- Claims custom hors email / email_verified / role déjà présents côté access.
- `/revoke` et `end_session` (autre spec).

## Critères d’acceptation

- Après la tranche, un client qui lit uniquement le discovery ne croit plus à tort qu’un `id_token` sera présent **ou** reçoit effectivement un `id_token` valide RS256.
- Les clients first-party existants continuent de fonctionner (régression interdite sur access token / userinfo).
- Tests : metadata discovery (A) **ou** présence + claims minimales + nonce (B).
