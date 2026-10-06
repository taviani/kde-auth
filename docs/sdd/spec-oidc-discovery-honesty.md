# kde-auth — honnêteté discovery OIDC (pas d’id_token annoncé)

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

**Priorité :** cassé / menteur. Le document `/.well-known/openid-configuration` annonce `id_token_signing_alg_values_supported` (RS256) alors que la réponse `/token` **n’émet jamais** d’`id_token`. Les claims d’identité (`email`, `email_verified`, `role`) vivent dans l’**access token** et `/userinfo`.

**Décision produit (verrouillée) : option A — discovery honnête.** On ne devient pas un IdP OIDC Core pour l’instant : tous les clients sont first-party et consomment déjà access JWT + userinfo. Émettre un vrai `id_token` (option B) est reporté ; ce n’est pas requis tant qu’aucun RP tiers / lib strict OIDC n’est au programme.

## Produit

L’issuer dit la vérité dans le discovery : **pas de signal de support ID Token** tant qu’aucun `id_token` n’est émis. Le profil reste : access token RS256 + `GET /userinfo`.

Les clients first-party (Portclos, Instacrane, etc.) ne changent pas.

## Processus

1. Retirer du metadata discovery les champs qui annoncent un ID Token (notamment `id_token_signing_alg_values_supported`).
2. Aligner README / docs : identité = access JWT + userinfo ; pas d’`id_token`.
3. Aucun changement de réponse `/token` (toujours sans `id_token`).

## Règles

- Ne jamais annoncer une capacité absente.
- `openid` reste obligatoire dans le scope (déjà le cas) — même sans `id_token`, le scope reste le marqueur OAuth/OIDC « login » pour nos clients.
- L’access token peut continuer à porter email / email_verified / role (compat first-party).
- Toute future tranche « vrai id_token » = **nouvelle** SDD, pas un glissement silencieux de celle-ci.

## API (issuer)

| Surface | Attendu |
|---------|---------|
| `GET /.well-known/openid-configuration` | sans `id_token_signing_alg_values_supported` (ni autres champs ID Token inventés) |
| `POST /token` | inchangé (pas d’`id_token`) |
| `GET /userinfo` | inchangé |

## Clients

Aucun changement obligatoire. Ils continuent d’utiliser access token / userinfo.

## Hors scope (cette version)

- Émettre un `id_token` / `nonce` / `auth_time`.
- `prompt`, `max_age`.
- Rotation de clés JWKS.
- `/revoke` et `end_session` (voir [spec-token-revoke-and-logout.md](spec-token-revoke-and-logout.md)).

## Critères d’acceptation

- Le discovery ne mentionne plus le support ID Token.
- `/token` ne renvoie toujours pas d’`id_token` (pas de régression « on a ajouté B par erreur »).
- Access token + userinfo inchangés pour les clients existants.
- Test : assertion sur le JSON discovery (absence de la clé ID Token).
- README aligné sur le comportement réel.
