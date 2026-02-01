from __future__ import annotations
import argparse, sys, json, os, telebot
from datetime import datetime, timezone
from lxml import etree
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509

# ==========================================
# KONFIGURASI BOT
# ==========================================
# Masukkan token bot Anda di sini
TOKEN = "YOUR_TOKEN_HERE"

# ==========================================
# LOGIKA VALIDASI KEYBOX
# ==========================================

def load_revocations(path):
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        # Map serial (lowercase hex) -> policy string
        return {str(s).lower(): d.get("policy", {}).get(str(s), "REVOKED") for s in d.get("serials", [])}
    except Exception as e:
        return {}

def load_trusted_root(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        return None

def verify_root_trust(chain_root, trusted_root):
    if not trusted_root:
        return True

    try:
        return chain_root.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) == trusted_root.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:
        return False

def load_certs(pems):
    certs = []
    for pem in pems:
        if not pem:
            continue
        try:
            certs.append(x509.load_pem_x509_certificate(pem))
        except Exception as e:
            pass
    return certs

def check_private_key(alg, pem):
    try:
        key = load_pem_private_key(pem, password=None)
        if alg == "ecdsa":
            return isinstance(key, ec.EllipticCurvePrivateKey)
        if alg == "rsa":
            return isinstance(key, rsa.RSAPrivateKey)
    except Exception:
        pass
    return False

def algo_name(cert):
    sig = (getattr(cert.signature_algorithm_oid, "_name", "") or "").lower()
    try:
        h = cert.signature_hash_algorithm.name.upper()
    except Exception:
        h = "UNKNOWN"
    if "ecdsa" in sig:
        return f"ECDSA with {h}"
    if "rsa" in sig or "rsassa" in sig:
        return f"RSA with {h}"
    return f"{sig} ({h})".strip()

def subject_str(cert):
    parts = []
    for r in cert.subject.rdns:
        for a in r:
            n = a.oid._name or a.oid.dotted_string
            if n and n.lower() in ("serialnumber", "title"):
                parts.append(f"{n}={a.value}")
    return ", ".join(parts) if parts else cert.subject.rfc4514_string()

def issuer_str(cert):
    parts = []
    for r in cert.issuer.rdns:
        for a in r:
            n = a.oid._name or a.oid.dotted_string
            if n and n.lower() in ("serialnumber", "title"):
                parts.append(f"{n}={a.value}")
    return ", ".join(parts) if parts else cert.issuer.rfc4514_string()

def verify_chain(certs):
    res = {}
    for i, c in enumerate(certs):
        checks = {
            "serial": True,
            "subject": True,
            "issuer": True,
            "signature": False,
            "not_expired": False,
            "in_chain": True,
        }
        now = datetime.now(timezone.utc)
        try:
            try:
                nb = c.not_valid_before_utc
                na = c.not_valid_after_utc
            except AttributeError:
                nb = c.not_valid_before.replace(tzinfo=timezone.utc)
                na = c.not_valid_after.replace(tzinfo=timezone.utc)
            checks["not_expired"] = (nb <= now <= na)
        except Exception:
            checks["not_expired"] = False

        issuer = None
        if c.issuer == c.subject:
            issuer = c
        else:
            for candidate in certs:
                if candidate.subject == c.issuer:
                    issuer = candidate
                    break

        if issuer:
            try:
                pub = issuer.public_key()
                if isinstance(pub, rsa.RSAPublicKey):
                    pub.verify(
                        c.signature,
                        c.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        c.signature_hash_algorithm,
                    )
                else:
                    pub.verify(
                        c.signature,
                        c.tbs_certificate_bytes,
                        ec.ECDSA(c.signature_hash_algorithm),
                    )
                checks["signature"] = True
            except Exception:
                checks["signature"] = False
        else:
            checks["in_chain"] = False
            checks["signature"] = False

        res[i] = checks
    return res

def hex_serial(c): return f"{c.serial_number:x}"
def fmt_dt(dt): return dt.strftime("%d/%b/%Y")

def check_keybox(xml_path, rev_path=None, root_path=None):
    output = []
    def log(msg=""):
        output.append(str(msg))

    revmap = load_revocations(rev_path)

    trusted_root = load_trusted_root(root_path)
    if trusted_root:
        log(f"🛡️ Trusted Root loaded from {os.path.basename(root_path)}")

    if not os.path.exists(xml_path):
        return f"🔴 File not found: {xml_path}"

    try:
        with open(xml_path, "rb") as f:
            xml = f.read()
    except Exception as e:
        return f"🔴 Error reading file: {e}"

    try:
        root = etree.fromstring(xml)
    except Exception as e:
        return f"🔴 XML tidak valid: {e}"

    kboxes = root.findall(".//Keybox")
    leaked = False
    log(f"💾 File: {os.path.basename(xml_path)}\n")
    if not kboxes:
        return "🔴 Tidak ada <Keybox> di XML."

    for kb_i, kb in enumerate(kboxes, start=1):
        keys = kb.findall("./Key")
        for ch_i, key in enumerate(keys, start=1):
            alg = (key.get("algorithm") or "").lower()
            log(f"🔑 Key Chain: #{ch_i}")

            if alg == "nbs":
                log("⚠️ Ignoring the NBS Key.")
                log("\n🔎 RESULT: 🔎\n")
                log(f"⚠️ Key Chain #{ch_i} ignored.")
                log("\n" + ("-" * 60) + "\n")
                continue

            # Private Key
            priv_node = key.find("./PrivateKey")
            valid_pk = False
            if priv_node is not None and (priv_node.text or "").strip():
                leaked = True
                pem = (priv_node.text or "").strip().encode()
                valid_pk = check_private_key(alg, pem)
                t = "EC" if alg == "ecdsa" else ("RSA" if alg == "rsa" else "Unknown")
                log(f"{'✅' if valid_pk else '🔴'} {'Valid' if valid_pk else 'Invalid'} {t} Private Key.")
            else:
                log("⚠️ Tanpa Private Key di XML.")

            # Certificate chain
            cert_nodes = key.findall("./CertificateChain/Certificate")
            pems = [(c.text or "").strip().encode() for c in cert_nodes]
            certs = load_certs(pems)

            has_certs = len(certs) > 0
            if not has_certs:
                log("⚠️ No certificates found in chain.")

            chain = verify_chain(certs)

            for i, c in enumerate(certs, start=1):
                log(f"\n🔐 Certificate: #{i}")
                s = hex_serial(c)
                log(f"ℹ️ Serial: {s}.")
                log(f"ℹ️ Subject: {subject_str(c)}.")
                log(f"ℹ️ Issuer: {issuer_str(c)}.")
                log(f"ℹ️ Signature Algorithm: {algo_name(c)}.")

                try:
                    nb = c.not_valid_before_utc
                    na = c.not_valid_after_utc
                except AttributeError:
                    nb = c.not_valid_before.replace(tzinfo=timezone.utc)
                    na = c.not_valid_after.replace(tzinfo=timezone.utc)
                log(f"ℹ️ Validity (GMT): From: {fmt_dt(nb)} To: {fmt_dt(na)}.")

                chk = chain.get(i-1, {})
                log(f"{'✅' if chk.get('in_chain') else '🔴'} Valid Chain.")
                log(f"{'✅' if chk.get('serial') else '🔴'} Valid Serial.")
                log(f"{'✅' if chk.get('subject') else '🔴'} Valid Subject.")
                log(f"{'✅' if chk.get('issuer') else '🔴'} Valid Issuer.")
                log(f"{'✅' if chk.get('signature') else '🔴'} Valid Signature.")
                log(f"{'✅' if chk.get('not_expired') else '🔴'} Not Expired.")
                if s.lower() in revmap:
                    log(f"🔴 REVOKED: {revmap[s.lower()]}.")
                else:
                    log("✅ Not Revoked.")

            chain_valid_tech = all(v.get("signature") and v.get("not_expired") for v in chain.values())
            not_revoked = not any(hex_serial(c).lower() in revmap for c in certs)

            # Trust Root Check
            is_trusted_root = True
            if trusted_root and certs:
                chain_root = certs[-1]
                is_trusted_root = verify_root_trust(chain_root, trusted_root)
                if not is_trusted_root:
                    log(f"🔴 Root Verification: FAILED. Root does not match trusted Google Root.")
                else:
                    log(f"✅ Root Verification: PASSED. Trusted Google Root.")

            strong_ok = (
                alg == "ecdsa"
                and valid_pk
                and has_certs
                and chain_valid_tech
                and not_revoked
                and is_trusted_root
            )

            basic_ok = (
                alg == "rsa"
                and valid_pk
                and has_certs
                and chain_valid_tech
                and not_revoked
                and is_trusted_root
            )

            softban = (
                alg == "ecdsa"
                and valid_pk
                and has_certs
                and any(hex_serial(c).lower() in revmap for c in certs)
            )

            log("\n🔎 RESULT: 🔎\n")
            if strong_ok:
                log(f"✅ Key Chain #{ch_i} VALID for STRONG integrity.")
            elif basic_ok:
                log(f"✅ Key Chain #{ch_i} VALID (Basic/RSA).")
            elif softban:
                log(f"❌ Key Chain #{ch_i} REVOKED/SOFTBANNED (Device ID or Cert revoked).")
            elif not has_certs:
                 log(f"❌ Key Chain #{ch_i} INVALID (No Certificates).")
            elif not is_trusted_root:
                log(f"❌ Key Chain #{ch_i} INVALID (Untrusted Root).")
            else:
                log(f"❌ Key Chain #{ch_i} INVALID.")
            log("\n" + ("-" * 60) + "\n")

    log("🚨 This KeyBox has been LEAKED." if leaked else "✅ No private keys embedded. Not flagged as leaked.")
    log("\n[ @KeyBox_Checker ] [ CI v1.1 ]")

    return "\n".join(output)

# ==========================================
# TELEGRAM BOT HANDLERS
# ==========================================

try:
    bot = telebot.TeleBot(TOKEN)
except Exception as e:
    print(f"⚠️ Warning: Bot initialization failed (probably invalid TOKEN). Script can still be imported. Error: {e}")
    bot = None

if bot:
    @bot.message_handler(commands=['start', 'help'])
    def send_welcome(message):
        bot.reply_to(message, "Halo! Kirimkan file Keybox XML untuk diperiksa.\n\n"
                              "Bot ini berjalan tanpa environment variable file (.env) sesuai permintaan.\n"
                              "Pastikan TOKEN di script sudah diisi.")

    @bot.message_handler(content_types=['document'])
    def handle_docs(message):
        temp_filename = None
        try:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)

            # Save to a temporary file
            safe_name = os.path.basename(message.document.file_name)
            # Avoid overwriting existing files or sensitive paths
            temp_filename = f"temp_{int(datetime.now().timestamp())}_{safe_name}"

            with open(temp_filename, 'wb') as new_file:
                new_file.write(downloaded_file)

            bot.reply_to(message, "File diterima, sedang memeriksa...")

            # Determine paths (same dir as this script)
            script_dir = os.path.dirname(os.path.abspath(__file__))
            default_revocations = os.path.join(script_dir, "revoked.json")
            default_root = os.path.join(script_dir, "google_root.pem")

            rev_path = default_revocations if os.path.exists(default_revocations) else None

            # Run check
            result = check_keybox(temp_filename, rev_path, default_root)

            # Telegram message limit is 4096.
            if len(result) > 4000:
                for x in range(0, len(result), 4000):
                    bot.reply_to(message, result[x:x+4000])
            else:
                bot.reply_to(message, result)

        except Exception as e:
            bot.reply_to(message, f"Terjadi kesalahan: {e}")
        finally:
            # Cleanup
            if temp_filename and os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except Exception:
                    pass

if __name__ == "__main__":
    if bot:
        print("Bot sedang berjalan... (Tekan Ctrl+C untuk berhenti)")
        try:
            bot.polling()
        except Exception as e:
            print(f"Error polling: {e}")
    else:
        print("❌ Bot not initialized. Please set a valid TOKEN in the script.")
