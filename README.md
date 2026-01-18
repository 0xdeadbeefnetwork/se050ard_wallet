# SE050ARD Bitcoin Wallet

**The first Bitcoin hardware wallet built on NXP SE050.** 

Private keys are stored in tamper-resistant silicon and **never leave the chip** - all signing happens on-device. This is a real hardware wallet using bank-grade secure element technology.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi-red.svg)
![Bitcoin](https://img.shields.io/badge/bitcoin-native%20segwit-orange.svg)
![First](https://img.shields.io/badge/SE050-first%20BTC%20wallet-green.svg)

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

## Why This Exists

**Nobody had done this before.**

The SE050 is a bank-grade secure element that's been available for years. It supports secp256k1 (Bitcoin's curve), has hardware TRNG, does on-chip ECDSA signing, and costs ~$2. Yet nobody built a Bitcoin wallet with it.

Until now.

Commercial hardware wallets cost $80-150 and are partially closed source. The SE050 eval kit costs ~$90, is fully documented, and now you have open source wallet software for it.

| What | SE050 | Ledger/Trezor |
|------|-------|---------------|
| Secure element | CC EAL6+ | ✅ Yes |
| secp256k1 signing | ✅ On-chip | ✅ On-chip |
| Hardware TRNG | ✅ AIS31 PTG.2 | ✅ Yes |
| Fully open source | ✅ **Yes** | Partial |
| Cost | ~$90 (dev kit) | ~$80-150 |
| Build it yourself | ✅ **Yes** | No |

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

# Build native library (optional but recommended - see below)
cd lib && ./build.sh && cd ..

# Run
./wallet_gui.py
```

See [INSTALL.md](INSTALL.md) for complete setup including NXP middleware.

---

## Building the Native Library

The native library requires NXP's Plug & Trust middleware to be built with SCP03 support.

### Prerequisites

```bash
# 1. Clone and build NXP middleware (one-time setup)
cd ~
git clone https://github.com/NXP/plug-and-trust.git simw-top
sudo mv simw-top /opt/simw-top
sudo chown -R $USER:$USER /opt/simw-top

# 2. Build middleware with SCP03 support
cd /opt/simw-top
mkdir -p build && cd build
cmake .. -DPTMW_SE05X_Auth=PlatfSCP03 -DPTMW_Host=Raspbian -DPTMW_SCP=SCP03_SSS
make -j$(nproc)

# 3. Install ssscli (also needed)
cd /opt/simw-top/pycli/src
pip3 install -e . --break-system-packages
```

### Build the Library

```bash
cd se050ard_wallet/lib

# Set middleware path
export SIMW_TOP_DIR=/opt/simw-top

# Build
./build.sh
```

Expected output:
```
==============================================
SE050 Wallet Native Library Build
==============================================
✓ Middleware has SCP03 support
Using middleware: /opt/simw-top
...
Build complete!
Library: .../lib/build/libse050_wallet.so
Symlink: .../lib/libse050_wallet.so
```

### Verify Backend

```bash
cd se050ard_wallet
python3 -c "from se050_interface import get_backend; print(f'Backend: {get_backend()}')"
```

Should print: `Backend: native`

If it prints `Backend: ssscli`, the library wasn't found - check the build output.

### Make it Permanent

Add to `~/.bashrc`:
```bash
echo 'export SIMW_TOP_DIR=/opt/simw-top' >> ~/.bashrc
source ~/.bashrc
```

### Library Location

The build creates:
```
se050ard_wallet/
└── lib/
    ├── build/
    │   └── libse050_wallet.so    # Actual library
    └── libse050_wallet.so        # Symlink (for easy finding)
```

The wallet auto-searches these paths:
- `./lib/libse050_wallet.so`
- `./lib/build/libse050_wallet.so`
- `~/se050ard_wallet/lib/build/libse050_wallet.so`
- `/usr/local/lib/libse050_wallet.so`

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

### This Is A Real Hardware Wallet

The SE050 is the same class of secure element used in:
- Bank cards and payment terminals
- Electronic passports
- Government ID cards
- Enterprise authentication tokens

**Your Bitcoin keys get the same protection.**

### What You Get

| Protection | Details |
|------------|---------|
| **CC EAL6+ certified** | Independent security certification - highest level for smartcards |
| **FIPS 140-2 Level 3** | US government cryptographic standard |
| **Keys never leave chip** | Private key cannot be extracted, even by you |
| **Hardware TRNG** | AIS31 PTG.2 certified true random number generator |
| **SCP03 encrypted channel** | AES-128 encrypted communication with the chip |
| **Tamper resistant** | Protected against physical attacks, power analysis, fault injection |

### Realistic Threat Model

**Generate your seed while offline, write it down, you're done.**

The theoretical attacks in other hardware wallet docs (evil maid, supply chain, etc.) require:
1. Attacker knows you have this specific hardware (SE050 + K64F + Pi)
2. Attacker has physical access to your running Pi
3. Attacker has malware specifically written for this platform (doesn't exist)
4. Attacker catches you with wallet unlocked

That's nation-state level targeting. For a DIY Bitcoin wallet. Be realistic.

### Best Practice

```bash
# Generate wallet offline (disconnect ethernet/wifi)
./wallet_gui.py

# Write down seed phrase on paper
# Reconnect to network
# Done - you have a hardware wallet
```

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

### 🔐 SCP03 Key Rotation (Advanced)

Default keys are published - anyone with physical access and knowledge of your SE050 variant could connect. **Rotating to your own keys prevents this.**

> **For most users: the default keys are fine.** Your SE050 is still protected - an attacker would need:
> 1. Physical access to your device
> 2. Knowledge that you have an SE050E specifically  
> 3. The default keys for that variant
>
> If your Pi isn't exposed to the internet and you control physical access, default keys are adequate.

⚠️ **WARNING**: If you rotate keys and lose them, the SE050 is **permanently locked**. There is no recovery.

#### How to Rotate Keys (Official NXP Method)

Key rotation uses NXP's `se05x_RotatePlatformSCP03Keys` demo from the Plug & Trust middleware (see [AN13013](https://www.nxp.com/docs/en/application-note/AN13013.pdf) Section 4.2).

**Prerequisites:**
- NXP Plug & Trust middleware **v02.12.01 or later** ([download from NXP](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-plug-trust-secure-element-family:SE050) - requires account)
- CMake, build tools
- Your current SCP03 keys (defaults are in the middleware)

**Step 1: Configure the middleware for your SE050E**

Edit `simw-top/sss/inc/fsl_sss_ftr.h.in` and enable the SE050E keys:

```c
// Set to 1 for SE050E (OM-SE050ARD-E board)
#define SSS_PFSCP_ENABLE_SE050E_0001A921 1

// Set all others to 0
#define SSS_PFSCP_ENABLE_SE050A1 0
#define SSS_PFSCP_ENABLE_SE050A2 0
// ... etc
```

The default SE050E keys are defined in `simw-top/sss/ex/inc/ex_sss_tp_scp03_keys.h`.

**Step 2: Build the middleware with SCP03 support**

```bash
cd simw-top
mkdir build && cd build

# For Raspberry Pi
cmake .. \
    -DPTMW_SE05X_Auth=PlatfSCP03 \
    -DPTMW_SCP=SCP03_SSS \
    -DPTMW_Applet=SE05X_E \
    -DPTMW_SE05X_Ver=07_02 \
    -DPTMW_Host=Raspbian \
    -DPTMW_SMCOM=T1oI2C

make -j4
```

**Step 3: Edit the key rotation demo with your new keys**

Edit `simw-top/demos/se05x/se05x_RotatePlatformSCP03Keys/se05x_RotatePlatformSCP03Keys.c`:

```c
// Generate new keys first: openssl rand -hex 16 (run 3 times)
// Then replace the NEW key arrays with your values:

static uint8_t NEW_ENC[] = {/* your 16 bytes in hex */};
static uint8_t NEW_MAC[] = {/* your 16 bytes in hex */};  
static uint8_t NEW_DEK[] = {/* your 16 bytes in hex */};
```

**Step 4: Run the rotation demo**

```bash
./bin/se05x_RotatePlatformSCP03Keys
```

**Step 5: Update your local key file**

```bash
cat > ~/.se050-wallet/scp03.key << EOF
ENC <your_new_enc_key_hex>
MAC <your_new_mac_key_hex>
DEK <your_new_dek_key_hex>
EOF
chmod 600 ~/.se050-wallet/scp03.key
```

**Step 6: Test the new keys**

```bash
ssscli connect se05x t1oi2c none \
    --auth_type PlatformSCP \
    --scpkey ~/.se050-wallet/scp03.key
ssscli se05x uid
ssscli disconnect
```

#### Optional: Make SCP03 Mandatory

After rotating keys, you can make SCP03 authentication **required** (plain communication disabled):

```bash
# Build and run the mandate demo
./bin/se05x_MandatePlatformSCP
```

⚠️ After this, the SE050 will **refuse all connections** without correct SCP03 keys.

To reverse (allow plain communication again):
```bash
./bin/se05x_AllowWithoutPlatformSCP
```

**References:**
- [AN13013: Get started with EdgeLock SE05x](https://www.nxp.com/docs/en/application-note/AN13013.pdf) - Section 4.2
- [NXP Community: Key rotation bug fix](https://community.nxp.com/t5/Secure-Authentication/SE050-key-rotation-demo-nxScp03-GP-InitializeUpdate-returns/td-p/1191062) (requires v02.12.01+)

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
