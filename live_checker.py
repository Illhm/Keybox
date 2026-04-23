import sys
import json
import requests
from datetime import datetime, timezone
from lxml import etree
from cryptography import x509

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

def get_security_level(cert):
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"))
        der = ext.value.value

        idx = 0
        if der[idx] != 0x30: return "Unknown"
        idx += 1

        if der[idx] & 0x80:
            len_bytes = der[idx] & 0x7F
            idx += 1 + len_bytes
        else:
            idx += 1

        if der[idx] != 0x02: return "Unknown"
        idx += 1

        length = der[idx]
        if length & 0x80:
            len_bytes = length & 0x7F
            idx += 1 + len_bytes
        else:
            idx += 1
        idx += length

        if der[idx] != 0x0A: return "Unknown"
        idx += 1

        length = der[idx]
        if length & 0x80:
            len_bytes = length & 0x7F
            idx += 1 + len_bytes
        else:
            idx += 1

        level = der[idx]

        if level == 0: return "Software"
        elif level == 1: return "TrustedEnvironment"
        elif level == 2: return "StrongBox"
        else: return f"Unknown ({level})"
    except x509.ExtensionNotFound:
        return "Not Found"
    except Exception as e:
        return f"Error ({e})"

def fetch_crl_with_progress():
    url = "https://android.googleapis.com/attestation/status"
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Downloading Google CRL...", total=None)

            response = requests.get(url, stream=True, timeout=15)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            if total_size > 0:
                progress.update(task, total=total_size)

            downloaded = 0
            chunks = []
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    chunks.append(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress.update(task, completed=downloaded)
                    else:
                        progress.update(task, advance=len(chunk))

            data = json.loads(b"".join(chunks))
            return data.get("entries", {})

    except Exception as e:
        console.print(f"[bold red]Failed to fetch CRL: {e}[/bold red]")
        return None

def analyze_keybox(xml_path):
    try:
        with open(xml_path, "rb") as f:
            xml_data = f.read()
        root = etree.fromstring(xml_data)
    except Exception as e:
        console.print(f"[bold red]Failed to parse XML: {e}[/bold red]")
        sys.exit(1)

    kboxes = root.findall(".//Keybox")
    if not kboxes:
        console.print("[bold red]No <Keybox> found in XML.[/bold red]")
        sys.exit(1)

    results = []

    for kb in kboxes:
        keys = kb.findall("./Key")
        for key in keys:
            certs = key.findall("./CertificateChain/Certificate")
            if not certs:
                continue

            leaf_pem = (certs[0].text or "").strip().encode()
            try:
                cert = x509.load_pem_x509_certificate(leaf_pem)
            except Exception as e:
                console.print(f"[bold red]Failed to load certificate: {e}[/bold red]")
                continue

            serial_int = cert.serial_number
            serial_hex = f"{serial_int:x}".lower()

            try:
                not_valid_after = cert.not_valid_after_utc
                not_valid_before = cert.not_valid_before_utc
            except AttributeError:
                not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                not_valid_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

            is_expired = datetime.now(timezone.utc) > not_valid_after

            sec_level = get_security_level(cert)

            results.append({
                "serial_hex": serial_hex,
                "serial_int": str(serial_int),
                "expired": is_expired,
                "expiry_date": not_valid_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "security_level": sec_level
            })

    return results

def main():
    if len(sys.argv) < 2:
        console.print("[bold red]Usage: python live_checker.py <path_to_keybox.xml>[/bold red]")
        sys.exit(1)

    xml_path = sys.argv[1]

    console.print(Panel.fit("[bold magenta]Live Keybox Integrity Checker[/bold magenta]", border_style="cyan"))

    console.print("\n[bold cyan]🔍 Analyzing Keybox Local Data...[/bold cyan]")
    keybox_data = analyze_keybox(xml_path)

    if not keybox_data:
        console.print("[bold yellow]No valid certificates found in the Keybox.[/bold yellow]")
        sys.exit(1)

    console.print("\n[bold cyan]🌐 Fetching Google CRL Real-Time...[/bold cyan]")
    crl_entries = fetch_crl_with_progress()

    if crl_entries is None:
        console.print("[bold red]Cannot proceed without CRL data.[/bold red]")
        sys.exit(1)

    for idx, data in enumerate(keybox_data, 1):
        serial_hex = data["serial_hex"]
        serial_int = data["serial_int"]
        sec_level = data["security_level"]
        is_expired = data["expired"]

        is_revoked = False
        revocation_reason = ""

        # Convert all serials to integers for reliable comparison, avoiding leading zero issues
        if str(serial_int) in crl_entries:
            is_revoked = True
            revocation_reason = crl_entries[str(serial_int)].get("reason", "REVOKED")
        elif serial_hex in crl_entries:
             is_revoked = True
             revocation_reason = crl_entries[serial_hex].get("reason", "REVOKED")
        else:
            for k, v in crl_entries.items():
                try:
                    crl_int = int(k, 16)
                    if crl_int == int(serial_int):
                        is_revoked = True
                        revocation_reason = v.get("reason", "REVOKED")
                        break
                except ValueError:
                    try:
                        crl_int = int(k)
                        if crl_int == int(serial_int):
                            is_revoked = True
                            revocation_reason = v.get("reason", "REVOKED")
                            break
                    except ValueError:
                        if k.lower() == serial_hex:
                            is_revoked = True
                            revocation_reason = v.get("reason", "REVOKED")
                            break

        if is_expired or is_revoked:
            overall_status = "[bold red]FAILED[/bold red]"
            if is_expired and not is_revoked:
                overall_status = "[bold red]EXPIRED[/bold red]"
            elif is_revoked:
                overall_status = "[bold red]REVOKED[/bold red]"
        else:
            if sec_level in ["TrustedEnvironment", "StrongBox"]:
                overall_status = "[bold green]STRONG[/bold green]"
            elif sec_level == "Software":
                overall_status = "[bold yellow]MEETS_DEVICE[/bold yellow]"
            else:
                overall_status = "[bold red]FAILED[/bold red]"

        table = Table(show_header=False, box=None)
        table.add_column("Property", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")

        table.add_row("Serial Number (Hex)", serial_hex)
        table.add_row("Expiry Date", data["expiry_date"])
        table.add_row("Expired", "[red]Yes[/red]" if is_expired else "[green]No[/green]")
        table.add_row("Security Level", sec_level)
        table.add_row("Revoked in CRL", f"[red]Yes ({revocation_reason})[/red]" if is_revoked else "[green]No[/green]")

        panel = Panel(
            table,
            title=f"Certificate #{idx}",
            title_align="left",
            border_style="blue",
            expand=False
        )
        console.print(panel)

        console.print(f"➜ OVERALL STATUS: {overall_status}\n")

if __name__ == "__main__":
    main()
