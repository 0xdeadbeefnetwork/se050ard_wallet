# SE050ARD Bitcoin Wallet

A Bitcoin hardware wallet using the NXP SE050 secure element. Private keys are stored in tamper-resistant silicon and **never leave the chip** - all signing happens on-device.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi-red.svg)
![Bitcoin](https://img.shields.io/badge/bitcoin-native%20segwit-orange.svg)

**Official NXP Setup Guide:** [AN13027 - EdgeLock SE05x Quick start guide](https://www.nxp.com/docs/en/application-note/AN13027.pdf)

**Tested and working on Bitcoin testnet4:**
```
TXID: fb2eca44409e391b60c5ca61456d0bb50ee9f30ad5ffe3e4cc9d02244c76deec
https://mempool.space/testnet4/tx/fb2eca44409e391b60c5ca61456d0bb50ee9f30ad5ffe3e4cc9d02244c76deec
```

---

## 🆕 What's New

### Native C Library (2.2x Faster!)
- **Direct SE050 interface** - no more subprocess overhead
- **Persistent SCP03 session** - connect once, sign many
- **~240ms per signature** vs ~530ms with ssscli
- **Automatic fallback** - works without native lib, just slower

### BIP39 Seed Phrase Support
- **Create wallets with 12 or 24 word seed phrases** - finally, a proper backup!
- **Import existing seed phrases** - restore from any BIP39 compatible wallet
- **BIP84 derivation** - standard `m/84'/0'/0'/0/0` path, works with Electrum, Sparrow, etc.
- **Hardware TRNG entropy** - seed phrases generated using SE050's AIS31 PTG.2 certified RNG

### Lazy Mode 🦥
- Skip seed verification (for testing/degen purposes)
- **Copy all words to clipboard** button
- Works with both 12 and 24 word seeds
- Big red "Skip Verification & Create" button

### Improved UI Performance
- **Non-blocking SE050 operations** - UI stays responsive during hardware calls
- **Async fee fetching** - Send dialog opens instantly, fees load in background
- **Async price fetching** - Fiat conversions don't freeze the UI
- **Threaded key checks** - No more UI hangs when checking key slots

---

## Why Native Library?

This wallet includes an optional native C library (`libse050_wallet.so`) that directly interfaces with the SE050 via NXP's middleware, rather than spawning `ssscli` subprocess calls.

| Metric | Native Library | ssscli Subprocess |
|--------|---------------|-------------------|
| **Sign latency** | ~240ms | ~530ms |
| **Speedup** | **2.2x faster** | baseline |
| **Connection** | Persistent session | Connect per-command |
| **Overhead** | Direct C calls | Python→subprocess→Python |

The native library:
- Keeps SE050 session open (no reconnect overhead)
- Uses mbedtls for public key derivation during import
- Builds SEC1 DER keys correctly for SE050
- Handles SCP03 authentication via NXP middleware

**Fallback**: If native library isn't built, the wallet automatically falls back to `ssscli` - everything still works, just slower.

---

## ⚠️ IMPORTANT: Backup Options

This wallet supports **two modes**:

### Option 1: BIP39 Seed Phrase (Recommended)
```
./wallet_gui.py → Keys tab → Create New Wallet
```
- Generates 12 or 24 word seed phrase using SE050 hardware TRNG
- **Write it down!** This is your backup
- Can restore to ANY BIP39 wallet (Electrum, Sparrow, BlueWallet, etc.)
- Key is derived from seed and written to SE050

### Option 2: SE050-Only (Legacy)
```
./wallet.py init
```
- Key generated and stored only on SE050
- **No seed phrase, no backup**
- Lose the chip = lose the funds

| Mode | Backup | Recovery | Security |
|------|--------|----------|----------|
| BIP39 Seed | ✅ Paper backup | ✅ Any BIP39 wallet | Seed can be stolen |
| SE050-Only | ❌ None | ❌ Impossible | Nothing to steal |

**Recommendation:** Use BIP39 seed phrases. The SE050 still protects your key during operation, but now you have a backup.

---

## Why Build This?

Most Bitcoin wallets store private keys in software - on disk, in memory, somewhere attackable. Commercial hardware wallets solve this but cost $80+ and are closed source.

The SE050 is a ~$2 secure element with:
- Hardware true random number generator (TRNG)
- Tamper-resistant key storage
- On-chip ECDSA signing (secp256k1)
- Open documentation

This project turns an SE050 eval kit into a functional Bitcoin hardware wallet.

---

## Hardware Requirements

```
+------------------+     USB      +------------------+     Arduino Headers
|  Raspberry Pi    |------------->|    FRDM-K64F     |<------------------->| SE050ARD |
|  (any model)     |              |    (MCU board)   |                     | (secure  |
|                  |              |                  |                     |  element)|
+------------------+              +------------------+                     +----------+
```

| Component | Part Number | Approx Cost |
|-----------|-------------|-------------|
| SE050 Dev Kit | OM-SE050ARD | $20 |
| K64F MCU Board | FRDM-K64F | $35 |
| Raspberry Pi | Any model | $35+ |

Total: ~$90 (reusable for other projects)

---

## Quick Start

```bash
# Clone
git clone https://github.com/yourusername/se050ard_wallet.git
cd se050ard_wallet

# Install Python deps
pip3 install -r requirements.txt --break-system-packages

# Build native library (optional but recommended - see INSTALL.md)
cd lib && ./build.sh && cd ..

# Run
./wallet_gui.py
```

See [INSTALL.md](INSTALL.md) for complete setup including NXP middleware and native library.

---

## Hardware Setup

### 1. Attach SE050ARD to K64F

The SE050ARD board connects via Arduino headers on the K64F:

```
        FRDM-K64F (Top View)
    +-------------------------+
    |  [USB]            [USB] |
    |   DBG              K64  |
    |                         |
    | [Arduino Headers]       |
    | | | | | | | | | | | | | |  <-- SE050ARD plugs in here
    | | | | | | | | | | | | | |
    |                         |
    +-------------------------+
```

Ensure the SE050ARD is fully seated. The SE050 chip communicates via I2C through the Arduino headers.

### 2. Flash K64F Firmware

The K64F needs NXP's "Virtual COM Port" firmware to bridge USB-to-I2C:

1. Hold the K64F reset button
2. Connect USB (the DBG port) - K64F appears as mass storage device
3. Drag-drop the vcom .bin file to the K64F drive
4. Release reset button

### 3. Connect K64F to Pi

Connect the K64F's **application USB port** (not debug port) to your Pi.

```bash
ls -la /dev/ttyACM*
# Should show /dev/ttyACM0
```

---

## Usage

### GUI Mode (Recommended)

```bash
./wallet_gui.py           # Mainnet
./wallet_gui.py --testnet # Testnet
```

The GUI provides:
- **Wallet creation with BIP39 seed phrases** (12 or 24 words)
- **Lazy mode** - skip verification, copy seed to clipboard 🦥
- **Import existing seed phrases**
- Balance display with USD conversion
- QR code for receiving
- Send dialog with fee estimation
- Message signing
- Transaction history
- SE050 verification

### CLI Mode

```bash
./wallet.py create              # 12 word seed (default)
./wallet.py create --words 24   # 24 word seed
./wallet.py import-seed         # Import existing seed
./wallet.py address             # Show addresses
./wallet.py balance             # Check balance
./wallet.py send <addr> <sats>  # Send Bitcoin
./wallet.py info                # SE050 status
```

### Testnet Mode

```bash
./wallet_gui.py --testnet
./wallet.py --testnet create
./wallet.py --testnet balance
```

### Multiple Wallets

Use different key slots:

```bash
./wallet.py --keyid 20000002 create
./wallet_gui.py --keyid 20000002
```

---

## Security

### ✅ What's Secure

| Feature | Status |
|---------|--------|
| **Private keys in SE050** | ✅ Keys never leave the secure element |
| **SCP03 encrypted channel** | ✅ All SE050 communication is AES-128 encrypted |
| **Tamper-resistant hardware** | ✅ SE050 is CC EAL6+ certified |
| **Signing in hardware** | ✅ ECDSA happens inside SE050 |
| **Hardware TRNG** | ✅ AIS31 PTG.2 certified random |
| **BIP-62 low-S signatures** | ✅ Normalized signatures (Bitcoin standard) |
| **No key extraction possible** | ✅ SE050 doesn't allow private key export |

### ⚠️ Limitations (vs Commercial Wallets)

| Issue | Risk | Mitigation |
|-------|------|------------|
| **Seed phrase shown on screen** | If Pi is compromised during creation, seed exposed | Use dedicated/air-gapped Pi |
| **No secure display** | Transaction details shown on Pi (could be spoofed) | Verify addresses carefully |
| **No physical confirmation** | No button press to approve transactions | Control physical access to Pi |
| **Pi is attack surface** | Malware could modify transactions | Harden Pi, firewall, updates |
| **SCP03 keys on filesystem** | `~/.se050-wallet/scp03.key` could be stolen | Proper file permissions (600) |

### 🆚 Compared To Commercial Wallets

| Feature | SE050ARD | Ledger/Trezor |
|---------|----------|---------------|
| Secure element | ✅ SE050 (CC EAL6+) | ✅ Yes |
| Encrypted comms | ✅ SCP03 | ✅ Yes |
| Secure display | ❌ No | ✅ Yes |
| Physical confirm | ❌ No | ✅ Button |
| Fully open source | ✅ Yes | Partial |
| Supply chain trust | ✅ You build it | Trust manufacturer |
| Cost | ~$90 (dev kit) | ~$80-150 |

### Recommended For

✅ Learning/education, small amounts, DIY/cypherpunk ethos, cold storage (air-gapped Pi)

❌ Not for: Large holdings, shared/remote access, non-technical users

---

## SCP03 Keys

### What Are SCP03 Keys?

SCP03 (Secure Channel Protocol 03) provides encrypted + authenticated communication with the SE050. Without the correct keys, you cannot access the chip.

### Default Keys by Variant

| Variant | Use Case | Default Keys |
|---------|----------|--------------|
| SE050A1/A2 | Development | Open (no auth required) |
| SE050C1/C2 | Production | NXP keys (requires NDA) |
| **SE050E** | Evaluation | Published in NXP docs |

### Key File Location

```
~/.se050-wallet/scp03.key
```

Format:
```
ENC <32 hex characters>
MAC <32 hex characters>
DEK <32 hex characters>
```

### Using Different Keys

**For a different SE050 variant**, edit the key file:
```bash
nano ~/.se050-wallet/scp03.key
```

**For multiple SE050 chips**, use separate key files:
```bash
export EX_SSS_BOOT_SCP03_PATH=~/.se050-wallet/scp03-chip2.key
./wallet_gui.py
```

### 🔐 Rotating Keys (Recommended!)

Default keys are published - anyone with physical access and knowledge of your SE050 variant could connect. **Rotating to your own keys prevents this.**

```bash
# 1. Generate new random keys
NEW_ENC=$(openssl rand -hex 16)
NEW_MAC=$(openssl rand -hex 16)
NEW_DEK=$(openssl rand -hex 16)

echo "=== SAVE THESE KEYS SECURELY ==="
echo "ENC $NEW_ENC"
echo "MAC $NEW_MAC"
echo "DEK $NEW_DEK"
echo "================================"

# 2. Connect with current keys
ssscli connect se05x vcom /dev/ttyACM0 \
    --auth_type PlatformSCP \
    --scpkey ~/.se050-wallet/scp03.key

# 3. Write new keys to SE050 (PERMANENT!)
ssscli se05x write-platformscp \
    --enc $NEW_ENC \
    --mac $NEW_MAC \
    --dek $NEW_DEK

# 4. Update your key file
cat > ~/.se050-wallet/scp03.key << EOF
ENC $NEW_ENC
MAC $NEW_MAC
DEK $NEW_DEK
EOF

chmod 600 ~/.se050-wallet/scp03.key

# 5. Test connection with new keys
ssscli disconnect
ssscli connect se05x vcom /dev/ttyACM0 \
    --auth_type PlatformSCP \
    --scpkey ~/.se050-wallet/scp03.key
ssscli se05x uid
```

⚠️ **CRITICAL**: If you rotate keys and lose them, the SE050 is **permanently locked**. Back up your keys securely!

---

## Hardening Your Setup

```bash
# 1. Secure key file permissions
chmod 600 ~/.se050-wallet/scp03.key
chmod 700 ~/.se050-wallet/

# 2. Enable firewall
sudo ufw enable
sudo ufw default deny incoming

# 3. Keep system updated
sudo apt update && sudo apt upgrade -y

# 4. Use dedicated Pi (not your daily driver)

# 5. For cold storage: disconnect network after setup
```

---

## Derivation Path

```
m/84'/0'/0'/0/0   - Mainnet (BIP84 Native SegWit)
m/84'/1'/0'/0/0   - Testnet
```

Compatible with any BIP84 wallet:
- Electrum (click "Options" → check "BIP39 seed")
- Sparrow Wallet
- BlueWallet
- Specter Desktop

**⚠️ Electrum Note:** When restoring in Electrum, you MUST click "Options" and check "BIP39 seed" - Electrum uses its own seed format by default.

---

## Architecture

```
wallet_gui.py / wallet.py
         │
         ▼
  se050_interface.py  (auto-selects backend)
         │
    ┌────┴────┐
    ▼         ▼
 native    ssscli
(~240ms)  (~530ms)
    │         │
    └────┬────┘
         ▼
   NXP Middleware (SCP03 Encrypted)
         │
         ▼
    FRDM-K64F (USB-VCOM)
         │
         ▼
      SE050E (Keys Here)
```

### Transaction Signing Flow

```
   Pi                          SE050
    |                            |
    | 1. Build unsigned TX       |
    | 2. Compute BIP-143 sighash |
    | 3. SHA256(sighash)         |
    |                            |
    |  single-SHA256 hash        |
    |--------------------------->|
    |                            | 4. SHA256 again (double-hash)
    |                            | 5. ECDSA sign with private key
    |                            |    (key never leaves chip)
    |                            |
    |  DER signature             |
    |<---------------------------|
    |                            |
    | 6. Normalize to low-S      |
    | 7. Assemble signed TX      |
    | 8. Broadcast to network    |
```

---

## Supported Features

| Feature | Status |
|---------|--------|
| **Native C library (2.2x faster)** | ✅ **NEW** |
| **SCP03 encrypted sessions** | ✅ **NEW** |
| **BIP39 seed phrases (12/24 words)** | ✅ Working |
| **Import existing seeds** | ✅ Working |
| **Lazy mode (skip verification)** | ✅ Working |
| Key generation (secp256k1) | ✅ Working |
| P2WPKH (Native SegWit) | ✅ Working |
| P2PKH (Legacy) | ✅ Working |
| Mainnet | ✅ Working |
| Testnet4 | ✅ Tested |
| Fee estimation | ✅ Working |
| Fiat price conversion | ✅ Working |
| QR code display | ✅ Working |
| Message signing | ✅ Working |
| Transaction history | ✅ Working |
| Multiple wallets | ✅ Via --keyid |
| BIP-62 low-S signatures | ✅ Normalized |
| Transaction broadcast | ✅ Via mempool.space |
| P2SH-P2WPKH (Wrapped SegWit) | ❌ Not implemented |
| Multisig | ❌ Not implemented |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection failed | Check USB, power cycle SE050 |
| SCP03 auth failed | Wrong keys for your variant, check key file |
| Backend: ssscli | Rebuild native lib: `cd lib && ./build.sh` |
| GUI won't start | `sudo apt install python3-tk` |
| Electrum wrong addresses | Click "Options" → check "BIP39 seed" |

---

## File Locations

```
~/.se050-wallet/
    scp03.key                  # SCP03 authentication keys
    pubkey_20000001.der        # DER-encoded public key
    pubkey_20000001.pem        # PEM-encoded public key  
    wallet_20000001.json       # Metadata (addresses, created timestamp)
```

---

## License

MIT

## Author

_SiCk @ [afflicted.sh](https://afflicted.sh)

## Contributing

Issues and PRs welcome. This is experimental software - use at your own risk.

---

⚠️ **Experimental software. Use at your own risk. Keep seed phrase backups!**

*"Not your keys, not your coins. Your keys in a secure element, backed up on paper, definitely your coins."*
