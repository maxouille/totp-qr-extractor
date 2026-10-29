# totp-qr-extractor

**Extract the secret keys behind any 2FA (TOTP) QR code — 100 % offline.**
**Récupérez les clés secrètes de n'importe quel QR code 2FA (TOTP) — 100 % hors ligne.**

Typical use: move your accounts from **Google Authenticator** to **Bitwarden / Vaultwarden** (or any other authenticator), or simply back up the secrets of a QR code you were shown once.

> Not affiliated with Google, Bitwarden or Vaultwarden. Names are used only to describe compatibility.
> Projet non affilié à Google, Bitwarden ou Vaultwarden ; les noms servent uniquement à décrire la compatibilité.

`2fa` `totp` `hotp` `otpauth` `qr-code` `google-authenticator` `bitwarden` `vaultwarden` `migration` `secret-key` `tkinter` `offline` `privacy`

---

## English

A small desktop app (Tkinter, one Python file) that reads 2FA QR codes locally and shows the secret keys.

**What it reads**

| Source | Format |
|---|---|
| Google Authenticator "Transfer accounts" export (also exported by e.g. Aegis) | `otpauth-migration://offline?data=…` (multi-QR batches supported) |
| The QR code a website shows when you enable 2FA | `otpauth://totp/…` and `otpauth://hotp/…` |

**How you give it the code**: image file, drag & drop, pasted screenshot (`Ctrl+V`), or paste the raw URI text.

**What you get**, per account: issuer, name, Base32 secret, TOTP/HOTP, algorithm, digits. Buttons copy the secret or the `otpauth://` URI. Export to **Bitwarden/Vaultwarden JSON** (recommended) or **CSV**, or a plain **list of `otpauth://` URIs** (`.txt`) that most authenticator apps can import.

**Privacy**: no networking code at all. Data lives in memory until *you* export.

### Install & run

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\python.exe -m pip install -r requirements.txt
.venv/bin/python totp_qr_extractor.py            # Windows: .venv\Scripts\python.exe totp_qr_extractor.py
```

`tkinterdnd2` only enables drag & drop (optional). On Linux, pasting a screenshot needs `xclip` or `wl-paste`.

### Migrating from Google Authenticator to Bitwarden

1. Google Authenticator: **Transfer accounts → Export**.
2. **Google splits exports into QR codes of 10 accounts each.** Load *every* QR one after another: accounts accumulate and the status bar tells you which QR is missing.
3. Export as **JSON**, then in Bitwarden/Vaultwarden: *Tools → Import data → Bitwarden (json)*.
4. **Delete the exported file securely** and clear your clipboard.

### Security notes

- Exports contain your **secrets in clear text**. Treat them like a password file.
- "In memory only" means the app writes nothing to disk. Python cannot reliably wipe strings from RAM, so close the app when done.
- The QR codes themselves hold the same secrets: do not keep screenshots of them.
- Audit it yourself: one file, no networking module imported.

### Tests

```bash
python -m unittest
```

Synthetic data only.

---

## Français

Petite application de bureau (Tkinter, un seul fichier Python) qui lit localement des QR codes 2FA et affiche les clés secrètes.

**Formats lus** : l'export « Transférer des comptes » de Google Authenticator (`otpauth-migration://…`, plusieurs QR gérés) et les QR classiques affichés par les sites à l'activation de la 2FA (`otpauth://totp/…`, `otpauth://hotp/…`).

**Entrées** : fichier image, glisser-déposer, capture collée (`Ctrl+V`) ou URI collée en texte.

**Exports** : JSON Bitwarden/Vaultwarden (recommandé), CSV, ou liste d'URI `otpauth://` (`.txt`).

### Installation et lancement

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe totp_qr_extractor.py
```

### Migrer de Google Authenticator vers Bitwarden

1. Google Authenticator : **Transférer des comptes → Exporter**.
2. **Google découpe l'export en QR codes de 10 comptes.** Chargez *tous* les QR l'un après l'autre ; la barre d'état indique celui qui manque.
3. Exportez en **JSON**, puis dans Bitwarden/Vaultwarden : *Outils → Importer des données → Bitwarden (json)*.
4. **Supprimez le fichier exporté** et videz le presse-papiers.

### Sécurité

- Les exports contiennent vos **secrets en clair**.
- « En mémoire uniquement » = rien n'est écrit sur disque. Python ne peut pas effacer la RAM de façon fiable : fermez l'appli une fois terminé.
- Ne gardez pas de captures des QR codes : elles contiennent les mêmes secrets.

## AI disclosure / Transparence IA

This project was written with the help of **Claude** (Anthropic), under the direction of its maintainer. Read the code and test it with fake data before trusting it with real secrets — it is a single, short file.

Ce projet a été écrit avec l'aide de **Claude** (Anthropic), sous la direction de son mainteneur. Lisez le code et testez-le avec de fausses données avant de lui confier de vrais secrets — c'est un seul fichier court.

## Licence / License

[MIT](LICENSE)
