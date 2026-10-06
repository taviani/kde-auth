# kde-auth — SDD

Source de vérité produit. On n’implémente une tranche qu’une fois sa spec validée, et seulement cette tranche.

## Principes (cible)

Issuer : **secure**, **agnostic**, **light**, **adaptable**, **feature-rich**, **performant**, **resilient**.

Quand deux principes se croisent, l’ordre de **planning** n’est pas philosophique : **ce qui est cassé ou menteur dans le contrat passe avant** les nouvelles features.

## File d’attente

| Priorité | Spec | Statut | Nature |
|----------|------|--------|--------|
| 1 | [Révoquer refresh après changement d’identifiants](spec-refresh-revoke-on-credential-change.md) | brouillon | cassé |
| 2 | [Honnêteté discovery / id_token](spec-oidc-discovery-honesty.md) | brouillon | cassé / menteur |
| 3 | [Respect de `offline_access`](spec-offline-access.md) | brouillon | cassé / menteur |
| 4 | [Suspendre un compte = couper les sessions](spec-suspend-revokes-sessions.md) | brouillon | cassé |
| 5 | [Édition d’un client OAuth](spec-edit-oauth-client.md) | brouillon | feature |
| 6 | [Révocation de jeton + fin de session OIDC](spec-token-revoke-and-logout.md) | brouillon | feature |
| 7 | [Double authentification (TOTP)](spec-2fa-totp.md) | brouillon | feature |

Déjà livré (référence) : [emails secondaires / récupération](spec-secondary-email.md).

## Règle de tranche

1. Valider la spec (ce fichier + la page concernée).
2. Plan d’implémentation court (defaults verrouillés).
3. Une PR = une tranche = une spec (ou un sous-ensemble explicite de la spec).
4. Pas d’UI client (Portclos / Instacrane) dans la même tranche sauf si la spec le dit.
