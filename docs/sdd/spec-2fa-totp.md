# kde-auth — double authentification (TOTP)

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

**Priorité :** feature (après correctifs « cassé » et de préférence après revoke/logout cohérents). Aujourd’hui : mot de passe (+ captcha) seulement.

## Produit

Le titulaire du compte peut activer une **deuxième facteur TOTP** (application d’authentification). Une fois activée, login issuer (et donc authorize) exige mot de passe **puis** code TOTP (ou code de secours).

Les clients OAuth ne gèrent pas le TOTP eux-mêmes : ils redirigent vers l’issuer. L’issuer reste la source de vérité du facteur.

## Processus — enrollment

1. Utilisateur authentifié (session ou Bearer, modèle à verrouiller au plan — **défaut proposé : session issuer pages HTML**, API Bearer possible en v2).
2. Demande d’activation → l’issuer crée un secret TOTP en attente, affiche QR / URI `otpauth`.
3. L’utilisateur confirme avec un premier code valide → facteur **actif** ; l’issuer affiche des **codes de secours** one-shot (à stocker hashés).
4. Tant que non confirmé : l’enrollment n’est pas actif (login inchangé).

## Processus — login

1. Email + mot de passe (+ captcha) comme aujourd’hui.
2. Si 2FA actif : étape supplémentaire « saisir le code » (pas de session complète avant succès TOTP ou backup).
3. Échec TOTP : pas de session ; rate-limit aligné sur le login.

## Processus — disable

1. Authentifié + mot de passe (et code TOTP courant si encore actif).
2. Désactivation : secret et backup invalidés.

## Règles

- TOTP : SHA1 / 30s / 6 digits (interop authenticator apps courantes).
- Codes de secours : usage unique ; régénération invalide les anciens.
- 2FA **optionnel** par compte en v1 (pas de mandatory global).
- Invite / register : pas de 2FA à l’inscription ; enrollment après compte actif.
- Reset password : après reset, **conserver** le 2FA (le facteur n’est pas le mot de passe). Si l’utilisateur a perdu TOTP + backup → flux support / admin hors v1 ou spec « recovery » séparée.
- Captcha reste sur la première étape login.

## Données

Secret TOTP chiffré ou protégé au repos ; backup codes hashés ; flag `totp_enabled` (ou équivalent). Détail au plan.

## API / UI (issuer)

| Surface (proposée) | Effet |
|--------------------|--------|
| Pages `/account/2fa/*` (session) | enroll, confirm, disable, backup |
| Login multi-étapes | password puis TOTP |
| (Optionnel v1) API Bearer | hors défaut — seulement si un client natif doit enroll sans cookie |

## Clients

Aucun changement OAuth : après login issuer réussi, authorize/code inchangés. Les apps ne stockent pas le secret TOTP.

## Hors scope (cette version)

- WebAuthn / passkeys.
- SMS / email OTP comme 2FA.
- 2FA obligatoire pour tous les comptes ou pour les admins seulement (peut être une tranche suivante).
- IdP initié « step-up » (`acr_values`) riche.
- Enroll depuis Portclos UI via API (sauf si ajouté explicitement au plan).

## Critères d’acceptation

- Sans 2FA : login inchangé.
- Avec 2FA : mot de passe seul ne crée pas de session.
- Code TOTP valide → session ; code faux → refus + rate-limit.
- Backup code : une fois, puis invalidé.
- Disable avec preuves → login redevient password-only.
- Authorize après session 2FA fonctionne comme aujourd’hui.
