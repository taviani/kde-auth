# kde-auth — révoquer les refresh après changement d’identifiants

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

**Priorité :** cassé. Aujourd’hui, changer ou réinitialiser le mot de passe révoque les **sessions cookie** mais laisse les **refresh tokens** (~30 jours) utilisables. Un refresh volé survit au changement de mot de passe. L’admin, lui, révoque déjà sessions **et** refresh.

## Produit

Après toute opération qui signifie « ces identifiants ne sont plus valides pour les sessions existantes », l’issuer doit invalider **toutes** les sessions navigateur **et** tous les refresh tokens du compte. Les access JWT déjà émis restent valides jusqu’à leur courte expiration (comportement actuel accepté).

## Processus

1. L’utilisateur change son mot de passe (`POST /account/password`) **ou** consomme un lien de reset (`POST /reset-password`).
2. L’issuer met à jour le hash du mot de passe.
3. L’issuer révoque toutes les sessions du user.
4. L’issuer révoque **tous** les refresh tokens du user (même chemin que l’action admin « revoke sessions »).
5. Les prochains `grant_type=refresh_token` échouent (`invalid_grant`). Un nouveau login / authorize est nécessaire pour obtenir un nouveau refresh.

## Règles

- Même politique pour change-password et reset-password (pas de demi-mesure côté reset « oublié »).
- Alignement volontaire avec l’admin : un seul comportement « kill sessions + refresh ».
- Les access tokens non expirés ne sont pas révoqués individuellement (pas de denylist dans cette version).
- Pas de message d’erreur nouveau pour les clients : le refresh échoue comme un refresh déjà révoqué / inconnu.

## API (issuer)

Pas de nouvelle route. Comportement renforcé sur les flux existants :

| Flux | Aujourd’hui | Attendu |
|------|-------------|---------|
| `POST /account/password` | sessions révoquées | sessions + refresh révoqués |
| `POST /reset-password` | sessions révoquées | sessions + refresh révoqués |
| Admin revoke | sessions + refresh | inchangé (référence) |

## Clients

Les apps qui stockent un refresh doivent déjà gérer `invalid_grant` (re-login). Aucun changement de contrat API côté clients au-delà de ce comportement déjà attendu après admin revoke.

## Hors scope (cette version)

- Révocation des access JWT avant `exp` (denylist / introspection).
- Réutilisation détectée d’un refresh (family wipe) — autre spec éventuelle.
- Suspend de compte (voir [spec-suspend-revokes-sessions.md](spec-suspend-revokes-sessions.md)).
- `/revoke` public RFC 7009 (voir [spec-token-revoke-and-logout.md](spec-token-revoke-and-logout.md)).

## Critères d’acceptation

- Après change-password réussi : aucun refresh du user n’est encore consommable.
- Après reset-password réussi : idem.
- Les sessions cookie sont toujours révoquées (régression interdite).
- Un test unitaire ou d’intégration prouve le revoke refresh sur les deux flux.
- L’action admin revoke reste comportementalement équivalente (pas de divergence).
