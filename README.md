# F5 VPN Login Automation

Automated F5 VPN login using Playwright with full Microsoft SSO and MFA support.

## Features

- **Automated Microsoft SSO** - Auto-fills username and password
- **TOTP MFA Support** - Auto-generates and enters 6-digit verification codes
- **Push Notification Fallback** - Displays MFA number for Authenticator app approval
- **Headless Mode** - Runs without browser window when fully automated
- **Session Extraction** - Automatically extracts VPN session and connects

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd f5-vpn

# The wrapper script will auto-setup on first run, or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## Configuration

Run the script with the `--init-config` option to generate `~/.f5-vpn.conf`:

```ini
[credentials]
username = your.email@example.com
password = yourpassword

# TOTP secret for fully automated MFA (optional)
totp_secret = YOURSECRETKEY
```

**Important:** Set file permissions to protect your credentials:
```bash
chmod 600 ~/.f5-vpn.conf
```

### Getting Your TOTP Secret

To enable fully automated login without phone interaction:

1. Go to [Microsoft Security Info](https://mysignins.microsoft.com/security-info)
2. Add or modify "Authenticator app"
3. Click **"I want to use a different authenticator app"**
4. Click **"Can't scan the QR code?"** to reveal the secret key
5. Copy just the secret value (e.g., `XXXXXXXXXXXXX`)

## Usage

### Basic Usage (Fully Automated with TOTP)

```bash
./f5-vpn
# or from anywhere:
~/f5-vpn
```

### Options

| Command | Description |
|---------|-------------|
| `~/f5-vpn` | Automated login (uses config file) |
| `~/f5-vpn -u email@example.com` | Override username |
| `~/f5-vpn --no-headless` | Show browser window |
| `~/f5-vpn --debug` | Enable debug output |
| `~/f5-vpn --manual` | Manual mode (prompts for session ID) |
| `~/f5-vpn --session <id>` | Direct mode with known session ID |
| `~/f5-vpn --init-config` | Create sample config file |

### Symlink for Easy Access

```bash
ln -sf /path/to/f5-vpn/f5-vpn ~/f5-vpn
```

## How It Works

1. **Navigates** to VPN portal → redirects to Microsoft SSO
2. **Fills credentials** automatically
3. **Selects MFA method**:
   - With TOTP secret: "Use a verification code" → auto-enters code
   - Without TOTP: "Approve on Authenticator" → displays number for manual approval
4. **Extracts session** cookie after successful login
5. **Connects to VPN** using `svpn-login`

## Requirements

- Python 3.10+
- [svpn-login](https://github.com/zrhoffman/svpn-login.git) at `~/git/svpn-login`
- F5 VPN client (`svpn`)

### Python Dependencies

```
playwright>=1.40.0
pyotp>=2.9.0
```

## Troubleshooting

### Debug Mode

Run with `--debug --no-headless` to see what's happening:

```bash
~/f5-vpn --debug --no-headless
```

### Common Issues

- **"svpn not found"** - Install F5 VPN client
- **"Session expired"** - Re-run the script
- **TOTP code rejected** - Ensure system clock is synced (`sudo sntp -sS time.apple.com`)

## Security Notes

- Credentials are stored in plain text in the config file
- Always use `chmod 600` on your config file
- Consider using a password manager or environment variables for sensitive data

## License

MIT
