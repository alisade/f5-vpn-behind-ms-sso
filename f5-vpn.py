#!/usr/bin/env python3
"""
Automated BAH VPN login using Playwright.
Opens a browser for manual authentication, then extracts the session ID
and passes it to svpn-login for VPN connection.

Config file: ~/.f5-vpn.conf
Format:
    [vpn]
    host = vpn.example.com
    
    [credentials]
    username = your.email@example.com
    password = yourpassword
    totp_secret = YOUR_BASE32_SECRET_KEY

Session cache: ~/.f5-vpn-session
    Cached session_id is reused for 8 hours to avoid re-authentication.
    Use --no-cache to force a fresh login.
"""

import argparse
import configparser
import getpass
import os
import subprocess
import sys
import re
import time
from typing import Optional
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

# Optional TOTP support
try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False


SVPN_LOGIN_DIR = os.path.expanduser("~/git/svpn-login")
SVPN_LOGIN_SCRIPT = os.path.join(SVPN_LOGIN_DIR, "svpn-login.py")
CONFIG_FILE = os.path.expanduser("~/.f5-vpn.conf")
SESSION_CACHE_FILE = os.path.expanduser("~/.f5-vpn-session")
SESSION_CACHE_TTL_SECONDS = 8 * 3600  # 8 hours


def load_config() -> dict:
    """
    Load configuration from ~/.f5-vpn.conf
    
    File format (INI-style):
        [vpn]
        host = vpn.example.com
        
        [credentials]
        username = your.email@example.com
        password = yourpassword
        totp_secret = YOUR_BASE32_SECRET
    """
    config = {'username': None, 'password': None, 'totp_secret': None, 'host': None}
    
    if not os.path.exists(CONFIG_FILE):
        return config
    
    try:
        # First try INI format with configparser
        cp = configparser.ConfigParser()
        cp.read(CONFIG_FILE)
        
        if cp.has_section('credentials'):
            config['username'] = cp.get('credentials', 'username', fallback=None)
            config['password'] = cp.get('credentials', 'password', fallback=None)
            config['totp_secret'] = cp.get('credentials', 'totp_secret', fallback=None)
        if cp.has_section('vpn'):
            config['host'] = cp.get('vpn', 'host', fallback=None)
        
        # Fallback: try simple key=value format if no sections found
        if not cp.has_section('credentials') and not cp.has_section('vpn'):
            with open(CONFIG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        if key in ('username', 'user', 'email'):
                            config['username'] = value
                        elif key in ('password', 'pass'):
                            config['password'] = value
                        elif key in ('totp_secret', 'totp', 'mfa_secret'):
                            config['totp_secret'] = value
                        elif key in ('host', 'vpn_host', 'server'):
                            config['host'] = value
        
        if config['username'] or config['password']:
            print(f"📁 Loaded credentials from {CONFIG_FILE}")
        if config['totp_secret']:
            print(f"🔑 TOTP secret configured")
        if config['host']:
            print(f"🌐 VPN host: {config['host']}")
            
    except Exception as e:
        print(f"⚠ Error reading config file: {e}")
    
    return config


def load_cached_session(host: str) -> Optional[str]:
    """
    Load session_id from ~/.f5-vpn-session if present and not older than 8 hours.
    Returns session_id only if cache exists, matches host, and is within TTL.
    """
    if not os.path.exists(SESSION_CACHE_FILE):
        return None
    try:
        with open(SESSION_CACHE_FILE, 'r') as f:
            data = {}
            for line in f:
                line = line.strip()
                if line and '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    data[key.strip()] = value.strip()
        session_id = data.get('session_id')
        cached_at_str = data.get('cached_at')
        cached_host = data.get('host', '')
        if not session_id or not cached_at_str:
            return None
        if cached_host and cached_host != host:
            return None
        cached_at = int(cached_at_str)
        if time.time() - cached_at > SESSION_CACHE_TTL_SECONDS:
            return None
        return session_id
    except (ValueError, OSError):
        return None


def save_cached_session(session_id: str, host: str) -> None:
    """Write session_id and timestamp to ~/.f5-vpn-session for reuse within 8 hours."""
    try:
        with open(SESSION_CACHE_FILE, 'w') as f:
            f.write(f"session_id={session_id}\n")
            f.write(f"cached_at={int(time.time())}\n")
            f.write(f"host={host}\n")
        os.chmod(SESSION_CACHE_FILE, 0o600)
    except OSError as e:
        print(f"⚠ Could not write session cache: {e}")


def create_sample_config():
    """Create a sample config file if it doesn't exist."""
    if os.path.exists(CONFIG_FILE):
        return
    
    sample = """# BAH VPN Configuration
# Stored at: ~/.f5-vpn.conf
# 
# WARNING: Credentials are stored in plain text. 
# Set file permissions: chmod 600 ~/.f5-vpn.conf
#
# You can omit password to be prompted each time.

[vpn]
host = vpn.example.com

[credentials]
username = your.email@example.com
# password = yourpassword

# TOTP secret for automatic MFA code generation
# To get your secret:
# 1. Go to https://mysignins.microsoft.com/security-info
# 2. Add/modify Authenticator app
# 3. Click "I want to use a different authenticator app"
# 4. Click "Can't scan the QR code?" to reveal the secret key
# totp_secret = YOURSECRETKEY
"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            f.write(sample)
        os.chmod(CONFIG_FILE, 0o600)  # Restrict permissions
        print(f"📝 Created sample config at {CONFIG_FILE}")
        print(f"   Edit it to add your credentials.")
    except Exception as e:
        print(f"⚠ Could not create sample config: {e}")

# JavaScript to extract MRHSession cookie after login
SESSION_EXTRACTOR_JS = """
() => {
    const match = document.cookie.match(/MRHSession=([^;]+)/);
    return match ? match[1] : null;
}
"""


DEBUG_MFA = os.environ.get('DEBUG_MFA', '').lower() in ('1', 'true', 'yes')


def generate_totp_code(secret: str) -> Optional[str]:
    """Generate TOTP code from secret key."""
    if not PYOTP_AVAILABLE:
        print("⚠ pyotp not installed. Run: pip install pyotp")
        return None
    
    try:
        # Clean the secret (remove spaces, dashes)
        secret = secret.replace(' ', '').replace('-', '').upper()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        if DEBUG_MFA:
            print(f"[DEBUG] Generated TOTP code: {code}")
        return code
    except Exception as e:
        print(f"⚠ Failed to generate TOTP code: {e}")
        return None


def enter_totp_code(page, code: str) -> bool:
    """
    Enter TOTP verification code on Microsoft MFA page.
    Returns True if code was entered successfully.
    """
    try:
        page.wait_for_timeout(1000)
        
        # Selectors for TOTP/OTP code input fields
        code_selectors = [
            'input#idTxtBx_SAOTCC_OTC',  # Microsoft "enter code" field
            'input[name="otc"]',
            'input[placeholder*="code"]',
            'input[placeholder*="Code"]',
            'input[aria-label*="code"]',
            'input[aria-label*="Code"]',
            'input[type="tel"][maxlength="6"]',
            'input[autocomplete="one-time-code"]',
        ]
        
        for selector in code_selectors:
            try:
                elem = page.locator(selector)
                if elem.count() > 0 and elem.first.is_visible(timeout=2000):
                    elem.first.fill(code)
                    print(f"✓ TOTP code entered")
                    if DEBUG_MFA:
                        print(f"[DEBUG] Used selector: {selector}")
                    
                    # Click verify/submit button
                    page.wait_for_timeout(500)
                    submit_selectors = [
                        '#idSubmit_SAOTCC_Continue',
                        'input[type="submit"][value*="Verify"]',
                        'input[type="submit"][value*="Sign"]',
                        'button[type="submit"]',
                        '#idSIButton9',
                    ]
                    
                    for submit_selector in submit_selectors:
                        try:
                            submit_btn = page.locator(submit_selector)
                            if submit_btn.count() > 0 and submit_btn.first.is_visible(timeout=1000):
                                submit_btn.first.click()
                                print("✓ Submitted TOTP code")
                                return True
                        except Exception:
                            continue
                    
                    return True
            except Exception as e:
                if DEBUG_MFA:
                    print(f"[DEBUG] Selector {selector} failed: {e}")
                continue
        
        if DEBUG_MFA:
            print("[DEBUG] No TOTP input field found")
        return False
        
    except Exception as e:
        if DEBUG_MFA:
            print(f"[DEBUG] enter_totp_code error: {e}")
        return False


def select_totp_mfa_option(page) -> bool:
    """
    Select the 'Use a verification code' MFA option for TOTP.
    Returns True if the option was selected.
    """
    try:
        page.wait_for_timeout(1000)
        
        current_url = page.url
        if 'microsoftonline' not in current_url and 'login.microsoft' not in current_url:
            return False
        
        # Look for "Use a verification code" option
        totp_selectors = [
            '[data-value="PhoneAppOTP"]',  # TOTP option
            'div[role="button"]:has-text("Use a verification code")',
            'div[role="button"]:has-text("verification code")',
            'div.tile:has-text("Use a verification code")',
            'div.tile:has-text("verification code")',
            'div:has-text("Use a verification code from my mobile app")',
        ]
        
        for selector in totp_selectors:
            try:
                elem = page.locator(selector)
                if elem.count() > 0 and elem.first.is_visible(timeout=1000):
                    elem.first.click()
                    print("✓ Selected 'Use a verification code' option")
                    return True
            except Exception:
                continue
        
        # Fallback: look for any element with "verification code" text
        try:
            code_options = page.locator('div:has-text("verification code")').all()
            for elem in code_options:
                try:
                    text = elem.text_content().lower()
                    if 'verification code' in text and elem.is_visible():
                        elem.click()
                        print("✓ Selected verification code option")
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        
        return False
        
    except Exception as e:
        if DEBUG_MFA:
            print(f"[DEBUG] select_totp_mfa_option error: {e}")
        return False


def extract_mfa_number_code(page, debug: bool = False) -> Optional[str]:
    """
    Extract the number matching code displayed on the MFA page.
    Microsoft Authenticator shows a 2-digit number that user must enter in the app.
    Returns the code string or None if not found.
    """
    debug = debug or DEBUG_MFA
    
    try:
        if debug:
            print("\n[DEBUG] Attempting to extract MFA code...")
            print(f"[DEBUG] Current URL: {page.url}")
        
        # Various selectors for the number matching display
        code_selectors = [
            '#idRichContext_DisplaySign',  # Common Microsoft selector for the number
            '.display-sign-container',
            'div[data-bind*="displaySign"]',
            '.displaySign',
            '#displaySign',
            '#idSIButton9',  # Sometimes near the button
            '.text-title',  # Title elements
            'div[role="heading"]',
        ]
        
        for selector in code_selectors:
            try:
                elem = page.locator(selector)
                count = elem.count()
                if debug and count > 0:
                    print(f"[DEBUG] Found {count} elements for selector: {selector}")
                if count > 0 and elem.first.is_visible(timeout=1000):
                    code = elem.first.text_content()
                    if debug:
                        print(f"[DEBUG]   Content: '{code}'")
                    if code and code.strip().isdigit() and len(code.strip()) <= 2:
                        return code.strip()
            except Exception as e:
                if debug:
                    print(f"[DEBUG]   Error with {selector}: {e}")
                continue
        
        # Try JavaScript to dump page info for debugging
        if debug:
            try:
                page_info = page.evaluate("""
                    () => {
                        const info = {
                            title: document.title,
                            bodyText: document.body.innerText.substring(0, 500),
                            hasDisplaySign: !!document.querySelector('#idRichContext_DisplaySign'),
                            allIds: Array.from(document.querySelectorAll('[id]')).map(e => e.id).slice(0, 30),
                        };
                        return info;
                    }
                """)
                print(f"[DEBUG] Page title: {page_info.get('title', 'N/A')}")
                print(f"[DEBUG] Has DisplaySign element: {page_info.get('hasDisplaySign', False)}")
                print(f"[DEBUG] Sample IDs on page: {page_info.get('allIds', [])[:15]}")
                print(f"[DEBUG] Page text preview:\n{page_info.get('bodyText', '')[:300]}")
            except Exception as e:
                print(f"[DEBUG] Error getting page info: {e}")
        
        # Fallback: try to find large number text on the page
        try:
            # Look for any element with just a 2-digit number
            all_text = page.locator('div, span').all_text_contents()
            two_digit_numbers = [t.strip() for t in all_text if t.strip().isdigit() and len(t.strip()) == 2]
            if debug and two_digit_numbers:
                print(f"[DEBUG] Found 2-digit numbers on page: {two_digit_numbers}")
            if two_digit_numbers:
                return two_digit_numbers[0]
        except Exception as e:
            if debug:
                print(f"[DEBUG] Error scanning text: {e}")
        
        # Try JavaScript extraction
        try:
            code = page.evaluate("""
                () => {
                    // Look for the display sign element
                    const signElem = document.querySelector('#idRichContext_DisplaySign');
                    if (signElem) return signElem.textContent.trim();
                    
                    // Look for any element with class containing 'display' and 'sign'
                    const elems = document.querySelectorAll('[class*="display"][class*="sign"], [class*="DisplaySign"]');
                    for (const elem of elems) {
                        const text = elem.textContent.trim();
                        if (text.length === 2 && /^\\d+$/.test(text)) return text;
                    }
                    
                    // Look for large text that's just a number
                    const bigText = document.querySelectorAll('h1, h2, .text-title, .title, [class*="Title"]');
                    for (const elem of bigText) {
                        const text = elem.textContent.trim();
                        if (text.length <= 2 && /^\\d+$/.test(text)) return text;
                    }
                    
                    return null;
                }
            """)
            if code:
                if debug:
                    print(f"[DEBUG] JS extraction found: {code}")
                return code
        except Exception as e:
            if debug:
                print(f"[DEBUG] JS extraction error: {e}")
        
        if debug:
            print("[DEBUG] No MFA code found on page")
        
        return None
        
    except Exception as e:
        if debug:
            print(f"[DEBUG] extract_mfa_number_code error: {e}")
        return None


def select_authenticator_app_mfa(page) -> bool:
    """
    Select the 'Approve a request on my Microsoft Authenticator app' MFA option.
    Returns True if the option was selected.
    """
    try:
        page.wait_for_timeout(1500)
        
        # Check if we're on Microsoft login/MFA page
        current_url = page.url
        if 'microsoftonline' not in current_url and 'login.microsoft' not in current_url:
            return False
        
        # Look for Microsoft Authenticator app option - various selectors
        authenticator_selectors = [
            # Data attribute selectors
            '[data-value="PhoneAppNotification"]',
            '[data-value="PhoneAppOTP"]',
            # Text-based selectors for the tile/button
            'div[role="button"]:has-text("Approve a request")',
            'div[role="button"]:has-text("Microsoft Authenticator")',
            'div.tile:has-text("Approve a request")',
            'div.tile:has-text("Microsoft Authenticator")',
            'div.row:has-text("Approve a request")',
            # ID-based selectors
            '#idDiv_SAOTCS_Proofs_498c5e86',
        ]
        
        for selector in authenticator_selectors:
            try:
                elem = page.locator(selector)
                if elem.count() > 0 and elem.first.is_visible(timeout=1000):
                    elem.first.click()
                    print("✓ Selected Microsoft Authenticator app option")
                    return True
            except Exception:
                continue
        
        # Fallback: try to find any element with "Authenticator" or "Approve" text
        try:
            auth_options = page.locator('div:has-text("Approve a request on my Microsoft Authenticator")').all()
            for elem in auth_options:
                try:
                    if elem.is_visible():
                        elem.click()
                        print("✓ Selected Microsoft Authenticator app option")
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        
        # Also try clicking on any Authenticator-related text
        try:
            auth_elem = page.locator('text=Microsoft Authenticator').first
            if auth_elem.is_visible(timeout=1000):
                auth_elem.click()
                print("✓ Selected Microsoft Authenticator option")
                return True
        except Exception:
            pass
        
        return False
        
    except Exception as e:
        print(f"⚠ Could not select Authenticator option: {e}")
        return False


def auto_fill_credentials(page, username: str, password: str) -> bool:
    """
    Attempt to auto-fill credentials on Microsoft SSO login page.
    Returns True if credentials were filled.
    """
    try:
        # Wait for the page to be on Microsoft login
        current_url = page.url
        if 'microsoftonline' not in current_url and 'login.microsoft' not in current_url:
            return False
        
        # Try to fill username field (Microsoft login)
        username_selectors = [
            'input[type="email"]',
            'input[name="loginfmt"]',
            '#i0116',
        ]
        
        for selector in username_selectors:
            try:
                if page.locator(selector).count() > 0:
                    elem = page.locator(selector)
                    if elem.is_visible(timeout=2000):
                        elem.fill(username)
                        print(f"✓ Username filled")
                        # Click Next button
                        page.locator('#idSIButton9').click()
                        page.wait_for_timeout(2000)
                        break
            except Exception:
                continue
        
        # Wait for password field to appear
        page.wait_for_timeout(1000)
        
        password_selectors = [
            'input[type="password"]',
            'input[name="passwd"]',
            '#i0118',
        ]
        
        for selector in password_selectors:
            try:
                if page.locator(selector).count() > 0:
                    elem = page.locator(selector)
                    if elem.is_visible(timeout=2000):
                        elem.fill(password)
                        print(f"✓ Password filled")
                        # Click Sign in button
                        page.locator('#idSIButton9').click()
                        page.wait_for_timeout(2000)
                        # MFA selection will be handled in the main loop
                        # based on whether TOTP secret is available
                        return True
            except Exception:
                continue
        
        return False
        
    except Exception as e:
        print(f"⚠ Could not auto-fill credentials: {e}")
        return False


def extract_session_from_url(url: str) -> Optional[str]:
    """Try to extract session ID from URL parameters."""
    match = re.search(r'MRHSession=([^&]+)', url)
    return match.group(1) if match else None


def wait_for_login_and_extract_session(page, username: str = None, password: str = None, 
                                        totp_secret: str = None, vpn_host: str = None) -> Optional[str]:
    """
    Wait for the user to complete login and extract the session ID.
    Returns the MRHSession cookie value.
    """
    print("\n" + "="*60)
    if username and password:
        print("Credentials provided - will auto-fill username and password.")
        if totp_secret:
            print("TOTP secret configured - will auto-generate MFA codes.")
        else:
            print("Will select Microsoft Authenticator for MFA.")
            print("Approve the notification on your phone when prompted.")
    else:
        print("Please log in to the VPN portal in the browser window.")
        print("Complete the Microsoft SSO authentication (including MFA).")
    print("The script will wait for you to return to the VPN portal.")
    print("="*60 + "\n")
    
    session_id = None
    max_wait_time = 300  # 5 minutes timeout for login
    check_interval = 2000  # Check every 2 seconds
    last_status = ""
    credentials_filled = False
    mfa_selected = False
    totp_entered = False
    
    for _ in range(max_wait_time * 1000 // check_interval):
        page.wait_for_timeout(check_interval)
        
        try:
            # Get current URL - this is safer than JavaScript evaluation during navigation
            current_url = page.url
            
            # Extract hostname from URL without JavaScript (safer during navigation)
            from urllib.parse import urlparse
            parsed = urlparse(current_url)
            current_host = parsed.netloc
            
            # Try to auto-fill credentials if on Microsoft login and not already done
            if not credentials_filled and username and password:
                if 'microsoftonline' in current_host or 'login.microsoft' in current_host:
                    credentials_filled = auto_fill_credentials(page, username, password)
                    if credentials_filled:
                        continue
            
            # Select MFA method based on whether we have TOTP secret
            if credentials_filled and not mfa_selected:
                if 'microsoftonline' in current_host or 'login.microsoft' in current_host:
                    if totp_secret:
                        mfa_selected = select_totp_mfa_option(page)
                    else:
                        mfa_selected = select_authenticator_app_mfa(page)
                    if mfa_selected:
                        continue
            
            # Enter TOTP code if we have a secret and haven't entered it yet
            if totp_secret and mfa_selected and not totp_entered:
                if 'microsoftonline' in current_host or 'login.microsoft' in current_host:
                    code = generate_totp_code(totp_secret)
                    if code:
                        totp_entered = enter_totp_code(page, code)
                        if totp_entered:
                            continue
            
            # Show waiting status while on Microsoft (waiting for MFA approval)
            if 'microsoftonline' in current_host or 'login.microsoft' in current_host:
                if credentials_filled:
                    if not totp_secret:
                        # Only show number matching for push notifications
                        mfa_code = extract_mfa_number_code(page)
                        if mfa_code:
                            status = f"📱 Enter this code in Microsoft Authenticator: [ {mfa_code} ]"
                            if status != last_status:
                                print("\n" + "="*50)
                                print(f"   🔢 MFA CODE: {mfa_code}")
                                print("="*50)
                                print("   Enter this number in your Authenticator app")
                                print("="*50 + "\n")
                                last_status = status
                        else:
                            status = "📱 Waiting for MFA approval on your phone..."
                            if status != last_status:
                                print(status)
                                last_status = status
                    else:
                        status = "🔐 Processing TOTP authentication..."
                        if status != last_status:
                            print(status)
                            last_status = status
                else:
                    status = f"⏳ Waiting for SSO completion... (on {current_host})"
                    if status != last_status:
                        print(status)
                        last_status = status
                continue
            
            # Only check for session when we're back on the VPN host (not Microsoft SSO)
            if vpn_host and vpn_host not in current_host:
                status = f"⏳ Waiting for SSO completion... (on {current_host})"
                if status != last_status:
                    print(status)
                    last_status = status
                continue
            
            # Check if we're on a logged-in page (webtop, vdesk, or my.policy)
            logged_in_indicators = ['/vdesk/', '/webtop', '/my.policy']
            is_logged_in_page = any(indicator in current_url for indicator in logged_in_indicators)
            
            if not is_logged_in_page:
                status = "⏳ Waiting for login to complete..."
                if status != last_status:
                    print(status)
                    last_status = status
                continue
            
            print(f"✓ Detected logged-in page: {current_url[:60]}...")
            
            # Wait a moment for cookies to be set
            page.wait_for_timeout(1000)
            
            # Now extract the session cookie
            cookies = page.context.cookies()
            for cookie in cookies:
                if cookie['name'] == 'MRHSession' and cookie['value'] != 'deleted':
                    session_id = cookie['value']
                    print(f"✓ Session cookie acquired!")
                    break
            
            if session_id:
                break
            
            # Fallback: try JavaScript extraction (wrapped in try/except for navigation safety)
            try:
                js_session = page.evaluate(SESSION_EXTRACTOR_JS)
                if js_session and js_session != 'deleted':
                    session_id = js_session
                    print(f"✓ Session extracted via JavaScript!")
                    break
            except Exception:
                pass
                
        except Exception as e:
            # Handle navigation errors gracefully - page might be redirecting
            if "context was destroyed" in str(e) or "navigation" in str(e).lower():
                continue
            # For other errors, log but continue
            print(f"⚠ Temporary error (retrying): {str(e)[:50]}")
            continue
    
    return session_id


def run_svpn_login(session_id: str, host: str):
    """Execute the svpn-login.py script with the session ID."""
    print(f"\n{'='*60}")
    print(f"Starting VPN connection with session: {session_id[:16]}...")
    print(f"{'='*60}\n")
    
    # Change to svpn-login directory and run the script
    env = os.environ.copy()
    
    # Activate the virtual environment by prepending its bin to PATH
    venv_bin = os.path.join(SVPN_LOGIN_DIR, "bin")
    env['PATH'] = f"{venv_bin}:{env.get('PATH', '')}"
    env['VIRTUAL_ENV'] = SVPN_LOGIN_DIR
    
    cmd = [
        os.path.join(venv_bin, "python3"),
        SVPN_LOGIN_SCRIPT,
        f"--sessionid={session_id}",
        host
    ]
    
    print(f"Running: {' '.join(cmd)}")
    
    try:
        subprocess.run(cmd, cwd=SVPN_LOGIN_DIR, env=env)
    except KeyboardInterrupt:
        print("\nVPN connection terminated by user.")
    except Exception as e:
        print(f"Error running svpn-login: {e}")
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description='BAH VPN Login Automation',
        epilog=f'Config file: {CONFIG_FILE} (username/password can be stored there)'
    )
    parser.add_argument('--username', '-u', help='Microsoft SSO username (email)')
    parser.add_argument('--password', '-p', help='Microsoft SSO password (will prompt if not provided)')
    parser.add_argument('--no-headless', action='store_true', help='Show browser window (default: headless when credentials provided)')
    parser.add_argument('--no-config', action='store_true', help='Ignore config file')
    parser.add_argument('--no-cache', action='store_true', help='Ignore cached session and log in again')
    parser.add_argument('--init-config', action='store_true', help='Create sample config file and exit')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug output for MFA extraction')
    return parser.parse_args()


def main():
    global DEBUG_MFA
    args = parse_args()
    
    # Handle --init-config
    if args.init_config:
        create_sample_config()
        return
    
    # Enable debug mode if requested
    if args.debug:
        DEBUG_MFA = True
        os.environ['DEBUG_MFA'] = '1'
        print("🔧 Debug mode enabled")
    
    # Load config file (unless --no-config)
    config = {} if args.no_config else load_config()
    
    # Get host from config or use default
    host = config.get('host') or "vpn.example.com"
    vpn_url = f"https://{host}"
    
    print(f"🔐 BAH VPN Login Automation")
    print(f"   Target: {vpn_url}")
    print()
    
    # Command-line args override config file
    username = args.username or config.get('username')
    password = args.password or config.get('password')
    totp_secret = config.get('totp_secret')
    
    if username and not password:
        password = getpass.getpass(f"Password for {username}: ")
    
    # Determine headless mode:
    # - Default to headless when credentials are provided (fully automated)
    # - Default to headed when no credentials (user needs to interact)
    # - --no-headless flag forces browser window visible
    if args.no_headless:
        headless = False
    else:
        # Auto-detect: headless if we have both username and password
        headless = bool(username and password)
    
    if headless:
        print("🖥️  Running in headless mode")
    else:
        print("🖥️  Running in headed mode (browser window visible)")
    
    # Try cached session first (unless --no-cache)
    if not args.no_cache:
        session_id = load_cached_session(host)
        if session_id:
            print(f"✓ Using cached session from {SESSION_CACHE_FILE} (valid for 8 hours)")
            run_svpn_login(session_id, host)
            return
    
    with sync_playwright() as p:
        # Launch browser
        browser = p.chromium.launch(
            headless=headless,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--start-maximized'
            ]
        )
        
        context = browser.new_context(
            viewport={'width': 1280, 'height': 900},
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        
        page = context.new_page()
        
        print(f"🌐 Navigating to {vpn_url}...")
        page.goto(vpn_url, wait_until='domcontentloaded')
        
        # Wait for user to log in and extract session
        session_id = wait_for_login_and_extract_session(page, username, password, totp_secret, host)
        
        if session_id:
            print(f"\n✓ Session ID obtained: {session_id[:16]}...")
            save_cached_session(session_id, host)
            browser.close()
            
            # Now run the VPN login with the session
            run_svpn_login(session_id, host)
        else:
            print("\n✗ Failed to obtain session ID. Please try again.")
            browser.close()
            sys.exit(1)


if __name__ == "__main__":
    main()

