#!/usr/bin/env python3
"""TOTP QR Extractor : extrait les clés secrètes 2FA d'un QR code, 100 % en local.

Formats lus : otpauth-migration:// (export Google Authenticator, Aegis…) et otpauth:// classique.
Exports : JSON/CSV Bitwarden/Vaultwarden, liste d'URI otpauth://.

- Aucune requête réseau, aucun fichier écrit sans action explicite (export).
- Décodage Protobuf inline (pas de .proto, pas de protobuf).
- QR : zxing-cpp + Pillow. Glisser-déposer : tkinterdnd2 (optionnel).
"""
import base64
import csv
import json
import sys
import tkinter as tk
import urllib.parse
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk

try:
    from PIL import Image, ImageGrab
except ImportError:
    sys.exit("Pillow manquant : pip install -r requirements.txt")
try:
    import zxingcpp
except ImportError:
    sys.exit("zxing-cpp manquant : pip install -r requirements.txt")
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    BaseTk = TkinterDnD.Tk
except Exception:  # glisser-déposer facultatif
    DND_FILES = None
    BaseTk = tk.Tk

# ----------------------------------------------------------------- Protobuf
# message MigrationPayload { repeated OtpParameters otp_parameters = 1;
#   int32 version = 2; int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5; }
# message OtpParameters { bytes secret = 1; string name = 2; string issuer = 3;
#   Algorithm algorithm = 4; DigitCount digits = 5; OtpType type = 6; int64 counter = 7; }
ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS = {0: 6, 1: 6, 2: 8}
TYPES = {0: "TOTP", 1: "HOTP", 2: "TOTP"}  # enum OtpType : 1=HOTP, 2=TOTP


def _varint(buf, pos):
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("Protobuf tronqué")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError("Varint invalide")


def _fields(buf):
    """Itère (numéro de champ, valeur) ; valeur = int ou bytes."""
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        num, wire = key >> 3, key & 7
        if wire == 0:
            val, pos = _varint(buf, pos)
        elif wire == 2:
            n, pos = _varint(buf, pos)
            if pos + n > len(buf):
                raise ValueError("Protobuf tronqué")
            val, pos = bytes(buf[pos:pos + n]), pos + n
        elif wire == 1:
            val, pos = int.from_bytes(buf[pos:pos + 8], "little"), pos + 8
        elif wire == 5:
            val, pos = int.from_bytes(buf[pos:pos + 4], "little"), pos + 4
        else:
            raise ValueError(f"Type de fil Protobuf non géré : {wire}")
        yield num, val


@dataclass
class Account:
    issuer: str
    name: str
    secret: str  # Base32 sans padding
    type: str = "TOTP"
    algorithm: str = "SHA1"
    digits: int = 6
    counter: int = 0

    @property
    def uri(self):
        label = urllib.parse.quote(f"{self.issuer}:{self.name}" if self.issuer else self.name, safe=":@")
        q = {"secret": self.secret}
        if self.issuer:
            q["issuer"] = self.issuer
        q["algorithm"] = self.algorithm
        q["digits"] = str(self.digits)
        if self.type == "HOTP":
            q["counter"] = str(self.counter)
        else:
            q["period"] = "30"
        return f"otpauth://{self.type.lower()}/{label}?{urllib.parse.urlencode(q, quote_via=urllib.parse.quote)}"

    @property
    def title(self):
        return self.issuer or self.name


def parse_otpauth_uri(uri):
    """URI otpauth://totp|hotp/Issuer:compte?secret=... -> même retour que parse_migration_uri."""
    parsed = urllib.parse.urlparse(uri.strip())
    kind = parsed.netloc.upper()
    if parsed.scheme != "otpauth" or kind not in ("TOTP", "HOTP"):
        raise ValueError("URI otpauth://totp/… ou otpauth://hotp/… attendue")
    q = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    if not q.get("secret"):
        raise ValueError("Paramètre « secret » absent de l'URI")
    secret = q["secret"].replace(" ", "").replace("-", "").upper().rstrip("=")
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8))
    except Exception:
        raise ValueError("Secret Base32 invalide")
    label = urllib.parse.unquote(parsed.path.lstrip("/"))
    issuer = q.get("issuer", "")
    if ":" in label:
        lab_iss, label = (s.strip() for s in label.split(":", 1))
        issuer = issuer or lab_iss
    algo = q.get("algorithm", "SHA1").upper().replace("-", "")
    return [Account(issuer=issuer, name=label, secret=secret, type=kind,
                    algorithm=algo if algo in ("SHA1", "SHA256", "SHA512", "MD5") else "SHA1",
                    digits=int(q["digits"]) if q.get("digits", "").isdigit() else 6,
                    counter=int(q["counter"]) if q.get("counter", "").isdigit() else 0)], 1, 0, 0


def parse_uri(uri):
    """Point d'entrée unique : migration ou otpauth simple."""
    uri = uri.strip()
    if uri.startswith("otpauth://"):
        return parse_otpauth_uri(uri)
    return parse_migration_uri(uri)


def parse_migration_uri(uri):
    uri = uri.strip()
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth-migration":
        raise ValueError("Ce n'est pas une URI otpauth-migration://")
    data = urllib.parse.parse_qs(parsed.query).get("data")
    if not data:
        raise ValueError("Paramètre « data » absent de l'URI")
    b64 = data[0].replace(" ", "+")  # '+' décodé en espace par parse_qs
    raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), altchars=b"-_" if "-" in b64 or "_" in b64 else None)
    accounts = []
    meta = {3: 1, 4: 0, 5: 0}  # batch_size, batch_index, batch_id
    for num, val in _fields(raw):
        if num in meta and isinstance(val, int):
            meta[num] = val
        if num != 1 or not isinstance(val, bytes):
            continue
        p = {"secret": b"", "name": "", "issuer": "", "alg": 1, "dig": 1, "typ": 2, "cnt": 0}
        for n, v in _fields(val):
            if n == 1:
                p["secret"] = v
            elif n == 2:
                p["name"] = v.decode("utf-8", "replace")
            elif n == 3:
                p["issuer"] = v.decode("utf-8", "replace")
            elif n == 4:
                p["alg"] = v
            elif n == 5:
                p["dig"] = v
            elif n == 6:
                p["typ"] = v
            elif n == 7:
                p["cnt"] = v
        name, issuer = p["name"], p["issuer"]
        if not issuer and ":" in name:  # ancien format « Issuer:compte »
            issuer, name = (s.strip() for s in name.split(":", 1))
        elif issuer and name.startswith(issuer + ":"):
            name = name[len(issuer) + 1:].strip()
        accounts.append(Account(
            issuer=issuer, name=name,
            secret=base64.b32encode(p["secret"]).decode().rstrip("="),
            type=TYPES.get(p["typ"], "TOTP"), algorithm=ALGORITHMS.get(p["alg"], "SHA1"),
            digits=DIGITS.get(p["dig"], 6), counter=p["cnt"]))
    if not accounts:
        raise ValueError("Aucun compte trouvé dans le payload")
    return accounts, meta[3], meta[4], meta[5]


def decode_qr(image):
    res = zxingcpp.read_barcodes(image.convert("RGB"))
    texts = [r.text for r in res if r.text.startswith(("otpauth-migration://", "otpauth://"))]
    if not texts:
        raise ValueError("Aucun QR code otpauth:// ou otpauth-migration:// détecté dans l'image")
    return texts


# ------------------------------------------------------------------- Export
CSV_HEADER = ["folder", "favorite", "type", "name", "notes", "fields", "reprompt",
              "login_uri", "login_username", "login_password", "login_totp"]


def export_csv(accounts, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_HEADER)
        for a in accounts:
            w.writerow(["", "", "login", a.title, "", "", 0, "", a.name, "", a.uri])


def export_json(accounts, path):
    items = [{
        "id": None, "organizationId": None, "folderId": None, "type": 1, "reprompt": 0,
        "name": a.title, "notes": None, "favorite": False,
        "login": {"uris": [], "username": a.name, "password": None, "totp": a.uri},
        "collectionIds": None} for a in accounts]
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"encrypted": False, "folders": [], "items": items}, f, ensure_ascii=False, indent=2)


def export_uris(accounts, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(chr(10).join(a.uri for a in accounts) + chr(10))


# --------------------------------------------------------------------- GUI
class App(BaseTk):
    def __init__(self):
        super().__init__()
        self.title("TOTP QR Extractor (100 % local)")
        self.geometry("820x560")
        self.accounts = []
        self.batches = {}  # batch_id -> [taille, indices chargés]
        self.reveal = tk.BooleanVar(value=False)

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Button(top, text="Charger une image QR…", command=self.load_image).pack(side="left")
        ttk.Button(top, text="Coller une capture (Ctrl+V)", command=self.paste_clipboard).pack(side="left", padx=6)
        ttk.Button(top, text="Vider", command=self.clear).pack(side="right")

        ttk.Label(self, text="…ou collez une ou plusieurs URI (otpauth-migration://… ou otpauth://…) ici :").pack(anchor="w", padx=8)
        row = ttk.Frame(self, padding=(8, 2))
        row.pack(fill="x")
        self.uri_entry = ttk.Entry(row, show="•")
        self.uri_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Décoder", command=self.decode_text).pack(side="left", padx=6)

        self.status = tk.StringVar(value="Prêt. Déposez une image ici ou utilisez les boutons." if DND_FILES
                                   else "Prêt. (Glisser-déposer indisponible : pip install tkinterdnd2)")
        ttk.Label(self, textvariable=self.status, foreground="#555").pack(anchor="w", padx=8, pady=4)

        cols = ("issuer", "name", "secret", "type", "algo", "digits")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse")
        for c, t, w in zip(cols, ("Service", "Compte", "Secret", "Type", "Algo", "Chiffres"),
                           (180, 220, 200, 60, 70, 60)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8)

        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ttk.Button(bar, text="Copier la clé secrète (Base32)", command=lambda: self.copy("secret")).pack(side="left")
        ttk.Button(bar, text="Copier l'URI otpauth://", command=lambda: self.copy("uri")).pack(side="left", padx=6)
        ttk.Checkbutton(bar, text="Afficher les secrets", variable=self.reveal, command=self.refresh).pack(side="left", padx=10)
        ttk.Button(bar, text="Exporter JSON Bitwarden…", command=lambda: self.export("json")).pack(side="right")
        ttk.Button(bar, text="Exporter URI (.txt)…", command=lambda: self.export("txt")).pack(side="right", padx=6)
        ttk.Button(bar, text="Exporter CSV Bitwarden…", command=lambda: self.export("csv")).pack(side="right", padx=6)

        self.bind_all("<Control-v>", lambda e: self.paste_clipboard() if self.focus_get() is not self.uri_entry else None)
        self.uri_entry.bind("<Return>", lambda e: self.decode_text())
        if DND_FILES:
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", lambda e: self.open_path(self.tk.splitlist(e.data)[0]))

    # --- entrées
    def load_image(self):
        p = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"), ("Tous", "*.*")])
        if p:
            self.open_path(p)

    def open_path(self, path):
        try:
            with Image.open(path) as im:
                im.load()
                self.ingest_image(im)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de lire l'image :\n{e}")

    def paste_clipboard(self):
        try:
            clip = ImageGrab.grabclipboard()
        except Exception as e:
            return messagebox.showerror("Erreur", f"Presse-papiers illisible :\n{e}")
        if isinstance(clip, Image.Image):
            self.ingest_image(clip)
        elif isinstance(clip, list) and clip:
            self.open_path(clip[0])
        else:
            messagebox.showinfo("Presse-papiers", "Aucune image dans le presse-papiers.")

    def decode_text(self):
        txt = self.uri_entry.get()
        self.uri_entry.delete(0, "end")
        if txt.strip():
            self.ingest_uris([u for u in txt.split() if u])

    def ingest_image(self, im):
        try:
            self.ingest_uris(decode_qr(im))
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def ingest_uris(self, uris):
        added = 0
        try:
            for u in uris:
                accs, size, idx, bid = parse_uri(u)
                self.batches.setdefault(bid, [size, set()])[1].add(idx)
                for a in accs:
                    if not any(x.secret == a.secret and x.name == a.name and x.issuer == a.issuer for x in self.accounts):
                        self.accounts.append(a)
                        added += 1
        except Exception as e:
            messagebox.showerror("Erreur de décodage", str(e))
        self.refresh()
        msg = f"{added} compte(s) ajouté(s) — {len(self.accounts)} au total."
        for size, got in self.batches.values():
            if size > 1:
                msg += f" Export en {size} QR (Google en met 10 comptes par QR) : {len(got)}/{size} chargés"
                msg += "." if len(got) >= size else f", il manque le(s) QR n°{sorted(i + 1 for i in set(range(size)) - got)}."
        self.status.set(msg)

    # --- affichage / actions
    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for i, a in enumerate(self.accounts):
            sec = a.secret if self.reveal.get() else "•" * 12
            self.tree.insert("", "end", iid=str(i), values=(a.issuer, a.name, sec, a.type, a.algorithm, a.digits))

    def selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Sélection", "Sélectionnez d'abord une ligne.")
            return None
        return self.accounts[int(sel[0])]

    def copy(self, what):
        a = self.selected()
        if a:
            self.clipboard_clear()
            self.clipboard_append(a.secret if what == "secret" else a.uri)
            self.update()
            self.status.set("Copié dans le presse-papiers (pensez à le vider ensuite).")

    def export(self, fmt):
        if not self.accounts:
            return messagebox.showinfo("Export", "Aucun compte à exporter.")
        if not messagebox.askyesno("Attention",
                                   "Le fichier exporté contiendra vos secrets TOTP EN CLAIR.\n"
                                   "Supprimez-le de façon sécurisée après l'import. Continuer ?"):
            return
        p = filedialog.asksaveasfilename(defaultextension=f".{fmt}", initialfile=f"totp_export.{fmt}")
        if p:
            {"csv": export_csv, "json": export_json, "txt": export_uris}[fmt](self.accounts, p)
            self.status.set(f"Exporté : {p}")

    def clear(self):
        self.accounts.clear()
        self.batches.clear()
        self.refresh()
        self.status.set("Mémoire vidée.")
        try:
            self.clipboard_clear()
        except tk.TclError:
            pass


if __name__ == "__main__":
    App().mainloop()
