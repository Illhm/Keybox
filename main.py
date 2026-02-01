from __future__ import annotations
import sys, os, json, time, telebot, requests, shutil
from datetime import datetime

# Add scripts directory to path to import keybox_checker
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts'))

try:
    from keybox_checker import check_keybox
except ImportError as e:
    print(f"Error importing keybox_checker: {e}")
    sys.exit(1)

# ==========================================
# KONFIGURASI BOT
# ==========================================
TOKEN = "YOUR_TOKEN_HERE"  # Replace with actual token or keep for user to fill

# Global Variables for CRL Caching
CRL_CACHE_FILE = "cached_revocations.json"
CRL_LAST_FETCH = 0
CRL_CACHE_DURATION = 3600  # 1 hour

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def get_realtime_crl_path():
    """
    Fetches the Android Attestation CRL from Google, converts it to the format
    expected by keybox_checker.py, and returns the path to the JSON file.
    Uses caching to avoid hitting the API on every request.
    """
    global CRL_LAST_FETCH

    # Check if cache is valid
    if os.path.exists(CRL_CACHE_FILE) and (time.time() - CRL_LAST_FETCH < CRL_CACHE_DURATION):
        return CRL_CACHE_FILE

    url = "https://android.googleapis.com/attestation/status"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        entries = data.get("entries", {})

        # Convert to format expected by keybox_checker:
        # {"serials": ["hex1", ...], "policy": {"hex1": "REASON", ...}}

        serials = []
        policy = {}

        for serial, details in entries.items():
            status = details.get("status", "REVOKED")
            reason = details.get("reason", "UNKNOWN")
            msg = f"{status} ({reason})"

            # Normalize serial to lowercase hex
            s_hex = None
            try:
                # Try decimal first
                s_int = int(serial)
                s_hex = f"{s_int:x}".lower()
            except ValueError:
                # Maybe it is already hex?
                try:
                    s_int = int(serial, 16)
                    s_hex = f"{s_int:x}".lower()
                except ValueError:
                    # Keep original if we can't parse (unlikely for valid serials)
                    s_hex = str(serial).lower()

            if s_hex:
                serials.append(s_hex)
                policy[s_hex] = msg

        crl_data = {
            "serials": serials,
            "policy": policy
        }

        with open(CRL_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(crl_data, f)

        CRL_LAST_FETCH = time.time()
        return CRL_CACHE_FILE

    except Exception as e:
        print(f"⚠️ Error fetching CRL: {e}")
        # Return existing cache if available, else None
        if os.path.exists(CRL_CACHE_FILE):
            return CRL_CACHE_FILE
        return None

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
                              "Bot ini menggunakan logika validasi terbaru (v1.4) dengan pengecekan CRL real-time.\n"
                              "Tanpa file .env.")

    @bot.message_handler(content_types=['document'])
    def handle_docs(message):
        temp_filename = None
        try:
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)

            safe_name = os.path.basename(message.document.file_name)
            temp_filename = f"temp_{int(datetime.now().timestamp())}_{safe_name}"

            with open(temp_filename, 'wb') as new_file:
                new_file.write(downloaded_file)

            status_msg = bot.reply_to(message, "File diterima, sedang memeriksa (mengambil CRL terbaru)...")

            # 1. Get CRL
            crl_path = get_realtime_crl_path()

            # 2. Get Root Path
            # Prefer local google_root.pem, fallback to scripts/google_root.pem
            root_path = "google_root.pem"
            if not os.path.exists(root_path):
                 root_path = os.path.join("scripts", "google_root.pem")

            # 3. Check Keybox using imported logic
            # This ensures we use the EXACT logic from the repo
            result = check_keybox(temp_filename, crl_path, root_path)

            # 4. Cleanup Output (Optional: add bot signature if not present)
            # The CLI script adds its own signature. We can append ours or leave it.

            # Send result
            # Telegram message limit is 4096 chars
            if len(result) > 4000:
                for x in range(0, len(result), 4000):
                    bot.reply_to(message, result[x:x+4000])
            else:
                bot.reply_to(message, result)

            # Delete processing message? Or just leave it.

        except Exception as e:
            bot.reply_to(message, f"Terjadi kesalahan: {e}")
        finally:
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
