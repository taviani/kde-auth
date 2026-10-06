# kde-auth — respect du scope `offline_access`

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

**Priorité :** cassé / menteur. Le scope `offline_access` est accepté (et documenté pour les apps natives), mais l’issuer **émet toujours** un refresh token. Au refresh, le scope renvoyé est hardcodé (`openid email`) et le scope d’origine n’est pas conservé.

## Produit

Un refresh token n’est émis **que** si le scope de l’autorisation inclut `offline_access`. Sinon, la réponse `/token` contient access token (+ éventuellement id_token selon autre spec) **sans** refresh. Les apps natives qui ont besoin d’une session longue demandent explicitement `offline_access`.

Le scope accordé est **persisté** avec le refresh et renvoyé à l’identique (ou en sous-ensemble cohérent) lors des renouvellements.

## Processus

1. `/authorize` avec `scope` contenant `openid` (± `email`, ± `offline_access`) — validation inchangée.
2. Échange `authorization_code` :
   - si `offline_access` présent → mint refresh, stocker le scope accordé ;
   - sinon → pas de refresh (champ absent ou vide selon convention JSON retenue au plan).
3. `grant_type=refresh_token` : consommer l’ancien refresh, émettre access (+ nouvel refresh si rotation conservée), renvoyer le **scope stocké** (pas un scope inventé).

## Règles

- `offline_access` sans `openid` : déjà invalidé par `ParseScope` (openid requis).
- Rotation refresh actuelle (consume puis mint) conservée quand un refresh est en jeu.
- Pas de refresh « gratuit » pour les clients confidentiels web qui n’ont pas demandé `offline_access`.
- Compat : les clients qui demandent déjà `… offline_access` ne changent rien ; ceux qui ne le demandaient pas mais stockaient un refresh **perdront** ce refresh — comportement voulu (contrat honnête).

## Données

Le refresh en base doit pouvoir retrouver le scope accordé (colonne ou équivalent). Détail SQL au plan d’implémentation.

## API (issuer)

| Surface | Attendu |
|---------|---------|
| `POST /token` (code, sans `offline_access`) | pas de `refresh_token` |
| `POST /token` (code, avec `offline_access`) | `refresh_token` + `scope` reflétant l’accord |
| `POST /token` (refresh) | `scope` = scope persisté ; nouveau refresh si rotation |

## Clients

- Apps natives (Portclos, etc.) : garder `offline_access` dans le scope authorize (déjà le cas typique).
- Clients web session-cookie only : ne pas demander `offline_access` ; ne pas s’attendre à un refresh.

## Hors scope (cette version)

- Détection de réutilisation d’un refresh (family wipe).
- Durées TTL refresh configurables par client.
- Consentement interactif distinct pour offline (pas d’écran consent OIDC dédié).

## Critères d’acceptation

- Authorize + token **sans** `offline_access` → aucune ligne refresh créée, réponse sans refresh utilisable.
- Avec `offline_access` → refresh émis ; un refresh ultérieur renvoie le même scope logique.
- README aligné sur le comportement réel.
- Tests pour les deux branches (avec / sans `offline_access`).
