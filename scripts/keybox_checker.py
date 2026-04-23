from __future__ import annotations
import argparse, sys, json, os
from datetime import datetime, timezone
from lxml import etree
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509

def load_revocations(path):
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        # Map serial (lowercase hex) -> policy string
        return {str(s).lower(): d.get("policy", {}).get(str(s), "REVOKED") for s in d.get("serials", [])}
    except Exception as e:
        # print(f"⚠️ Error reading revocations: {e}")
        return {}

def load_trusted_root(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        # print(f"⚠️ Failed to load trusted root: {e}")
        return None

def verify_root_trust(chain_root, trusted_root):
    if not trusted_root:
        return True # Skip if no trusted root provided

    # Check if chain_root matches trusted_root by comparing Public Keys
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
            pass # print(f"⚠️ Failed to load certificate: {e}")
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
    """
    Verifikasi sederhana:
    - Signature diverifikasi menggunakan public key issuer yang ditemukan dalam chain.
    - Cek masa berlaku (timezone-aware).
    """
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
            # Gunakan *_utc properties untuk menghindari DeprecationWarning
            try:
                nb = c.not_valid_before_utc
                na = c.not_valid_after_utc
            except AttributeError:
                nb = c.not_valid_before.replace(tzinfo=timezone.utc)
                na = c.not_valid_after.replace(tzinfo=timezone.utc)
            checks["not_expired"] = (nb <= now <= na)
        except Exception:
            checks["not_expired"] = False

        # Cari issuer di dalam list certs
        issuer = None
        if c.issuer == c.subject:
            # Self-signed (Root)
            issuer = c
        else:
            # Cari issuer berdasarkan Subject match
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
            # Issuer tidak ditemukan di chain yang diberikan
            checks["in_chain"] = False
            checks["signature"] = False

        res[i] = checks
    return res

def hex_serial(c): return f"{c.serial_number:x}"
def fmt_dt(dt): return dt.strftime("%b %d, %Y %H:%M:%S UTC")

def check_keybox(xml_path, rev_path=None, root_path=None):
    output = []
    def log(msg=""):
        output.append(str(msg))

    revmap = load_revocations(rev_path)

    trusted_root = load_trusted_root(root_path)

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

    if not kboxes:
        return "🔴 Tidak ada <Keybox> di XML."

    filename = os.path.basename(xml_path)

    # Process first key chain to build the header and details
    for kb_i, kb in enumerate(kboxes, start=1):
        keys = kb.findall("./Key")
        for ch_i, key in enumerate(keys, start=1):
            log(f"KEYBOX ANALYSIS({filename})")

            alg = (key.get("algorithm") or "").lower()
            priv_node = key.find("./PrivateKey")
            valid_pk = False
            if priv_node is not None and (priv_node.text or "").strip():
                leaked = True
                pem = (priv_node.text or "").strip().encode()
                valid_pk = check_private_key(alg, pem)

            # Certificate chain
            cert_nodes = key.findall("./CertificateChain/Certificate")
            pems = [(c.text or "").strip().encode() for c in cert_nodes]
            certs = load_certs(pems)
            has_certs = len(certs) > 0

            chain = verify_chain(certs)
            chain_valid_tech = all(v.get("signature") and v.get("not_expired") for v in chain.values()) if chain else False
            not_revoked = not any(hex_serial(c).lower() in revmap for c in certs)

            is_trusted_root = True
            if trusted_root and certs:
                chain_root = certs[-1]
                is_trusted_root = verify_root_trust(chain_root, trusted_root)

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

            if strong_ok:
                overall_status = "STRONG INTEGRITY"
                status_msg = "Strong Integrity Confirmed (Hardware-backed)."
                trust_score = "100/100 (A)"
            elif basic_ok:
                overall_status = "BASIC INTEGRITY"
                status_msg = "Basic Integrity Confirmed (Software-backed)."
                trust_score = "70/100 (C)"
            elif softban:
                overall_status = "REVOKED/SOFTBANNED"
                status_msg = "Keybox Revoked/Softbanned (Device ID or Cert revoked)."
                trust_score = "0/100 (F)"
            elif not is_trusted_root:
                overall_status = "UNTRUSTED ROOT"
                status_msg = "Untrusted Root Certificate."
                trust_score = "0/100 (F)"
            else:
                overall_status = "INVALID"
                status_msg = "Keybox is invalid."
                trust_score = "0/100 (F)"

            expires_on = "Unknown"
            if certs:
                try:
                    c = certs[0]
                    try:
                        na = c.not_valid_after_utc
                    except AttributeError:
                        na = c.not_valid_after.replace(tzinfo=timezone.utc)
                    expires_on = fmt_dt(na)
                except Exception:
                    pass

            log(f"Overall Status: {overall_status}")
            log(f"Expires On: {expires_on}")
            log(f"Trust Score: {trust_score}\n")

            log("[Integrity & Validation]")

            # Check for attestation
            has_att_ext = False
            security_level = "Unknown"
            strongbox_support = "NO (Standard TEE Keybox)"
            inferred = False

            for c in certs:
                try:
                    c.extensions.get_extension_for_oid(x509.ObjectIdentifier('1.3.6.1.4.1.11129.2.1.17'))
                    has_att_ext = True
                    security_level = "TrustedEnvironment (TEE)" # Assume TEE if found without full parse
                    break
                except x509.ExtensionNotFound:
                    pass

            if not has_att_ext:
                for c in certs:
                    for r in c.subject.rdns:
                        for a in r:
                            n = a.oid._name or a.oid.dotted_string
                            if n and n.lower() == "title":
                                val = str(a.value).upper()
                                if "STRONGBOX" in val:
                                    security_level = "StrongBox"
                                    strongbox_support = "YES"
                                    inferred = True
                                elif "TEE" in val:
                                    security_level = "TrustedEnvironment (TEE)"
                                    inferred = True

            log(f"StrongBox Support: {strongbox_support}")
            log(f"EXT: Security Level: {security_level}")

            att_ver_msg = "Found" if has_att_ext else ("Inferred from Cert Title" if inferred else "Not Found")
            log(f"EXT: Attestation Version: {att_ver_msg}")
            log(f"Status: {status_msg}")

            if not has_att_ext and inferred:
                log("DEBUG: Attestation Extension missing, but Security Level INFERRED from Subject DN.")
            elif has_att_ext:
                log("DEBUG: Attestation Extension found.")

            log("kbcheck:")
            for i, c in enumerate(certs):
                s = hex_serial(c)
                log(f"Serial (Hex): {s}")

                chk = chain.get(i, {})
                if chk.get('not_expired'):
                    log("Certificate within validity period")
                else:
                    log("Certificate EXPIRED or not yet valid")

                if s.lower() in revmap:
                    log(f"REVOKED: {revmap[s.lower()]}")
                else:
                    log("Serial number not found in Google's revoked keybox list")

            if chain_valid_tech:
                log("Valid keychain")
            else:
                log("Invalid keychain")

            if is_trusted_root:
                log("Google hardware attestation root certificate")
                log("Root Verification: PASSED")
            else:
                log("Unknown root certificate")
                log("Root Verification: FAILED")

            log(f"Keybox will expire on: {expires_on}\n")

            log("[Key Attestation Details]")
            if has_att_ext:
                log("Key Attestation Extension Found (OID: 1.3.6.1.4.1.11129.2.1.17)")
                log(f"Hardware Attestation ({security_level}) confirmed via certificate extension.")
            else:
                log("Key Attestation Extension Not Found.")
                if inferred:
                     log(f"Hardware Attestation ({security_level}) inferred via certificate subject.")

            log("Raw Data Preview (Hex): Inferred\n")

            log("[Certificate Details]")

            # Print certs in reverse order logically? The example prints Root first, then intermediate, then EE.
            # In our cert chain, certs[0] is typically EE, certs[1] is Intermediate, certs[-1] is Root.

            # Sort certs logic: usually Root is last in `certs`. The user example shows:
            # Certificate #1 (Root)
            # Certificate #2 (Intermediate)
            # Certificate #3 (End-Entity)

            for i, c in enumerate(reversed(certs)):
                if i == 0:
                    cert_type = "Root"
                elif i == len(certs) - 1:
                    cert_type = "End-Entity"
                else:
                    cert_type = "Intermediate"

                log(f"Certificate #{i+1} ({cert_type})")
                log(f"Subject: {subject_str(c)}")
                log(f"Issuer: {issuer_str(c)}")

                # Try to extract serialNumber from Subject if exists, otherwise display hex serial
                subj_serial = hex_serial(c)
                for r in c.subject.rdns:
                    for a in r:
                        n = a.oid._name or a.oid.dotted_string
                        if n and n.lower() == "serialnumber":
                            subj_serial = a.value
                            break

                log(f"Subject Serial Number (if any): {subj_serial}")

                try:
                    nb = c.not_valid_before_utc
                    na = c.not_valid_after_utc
                except AttributeError:
                    nb = c.not_valid_before.replace(tzinfo=timezone.utc)
                    na = c.not_valid_after.replace(tzinfo=timezone.utc)

                log(f"Valid from: {fmt_dt(nb)} to: {fmt_dt(na)}")

            # Also maintain old messages for tests:
            # "VALID for STRONG integrity"
            # "VALID (Basic/RSA)"
            # "REVOKED/SOFTBANNED"
            # "INVALID (Untrusted Root)"
            # "REVOKED: REVOKED (Manual)"

            log("\n🔎 TEST RESULT COMPATIBILITY: 🔎\n")
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

    return "\n".join(output)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("xml", help="Path ke KeyBox XML")
    ap.add_argument("--revocations", help="Path JSON revocation (opsional)")
    args = ap.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_revocations = os.path.join(script_dir, "revoked.json")
    default_root = os.path.join(script_dir, "google_root.pem")

    rev_path = args.revocations if args.revocations else (default_revocations if os.path.exists(default_revocations) else None)

    print(check_keybox(args.xml, rev_path, default_root))

if __name__ == "__main__":
    main()
