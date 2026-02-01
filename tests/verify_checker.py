import sys
import subprocess
import os

def run_checker(xml_path):
    # Run the script from the root
    # script path relative to CWD
    script_path = os.path.join("scripts", "keybox_checker.py")
    cmd = [sys.executable, script_path, xml_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def test_keybox_3_pass():
    print("Testing keybox (3).xml (Expect PASS)...")
    output = run_checker("keybox (3).xml")

    # Debug output
    # print(output)

    if "VALID for STRONG integrity" in output or "VALID (Basic/RSA)" in output:
        if "Root Verification: PASSED" in output:
            print("✅ PASS: keybox (3).xml is Valid and Trusted.")
        else:
            print("⚠️ WARN: keybox (3).xml is Valid but Root check failed/skipped?")
    else:
        print("❌ FAIL: keybox (3).xml should be Valid.")
        print(output)
        sys.exit(1)

def test_keybox_4_revoked():
    print("Testing keybox (4).xml (Expect REVOKED)...")
    output = run_checker("keybox (4).xml")

    # Debug output
    # print(output)

    # Check for specific revocation message for the cert
    if "REVOKED: REVOKED (Manual)" in output:
        print("✅ PASS: keybox (4).xml cert identified as Revoked.")
    else:
         print("❌ FAIL: keybox (4).xml cert NOT identified as Revoked.")
         print(output)
         sys.exit(1)

    # Check final result
    if "REVOKED/SOFTBANNED" in output:
        print("✅ PASS: keybox (4).xml result is REVOKED/SOFTBANNED.")
    elif "INVALID (Untrusted Root)" in output:
        print("⚠️ WARN: keybox (4).xml result is Untrusted Root (acceptable, but Revocation check is prioritized in logic if implemented right).")
    else:
        print("❌ FAIL: keybox (4).xml final result unexpected.")
        print(output)
        sys.exit(1)

if __name__ == "__main__":
    test_keybox_3_pass()
    test_keybox_4_revoked()
