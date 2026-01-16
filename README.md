# SE050ARD Bitcoin Wallet

A Bitcoin hardware wallet using the NXP SE050 secure element. Private keys are stored in tamper-resistant silicon and **never leave the chip** - all signing happens on-device.

**Official NXP Setup Guide:** [AN13027 - EdgeLock SE05x Quick start guide](https://www.nxp.com/docs/en/application-note/AN13027.pdf)

**Tested and working on Bitcoin testnet4:**
```
TXID: fb2eca44409e391b60c5ca61456d0bb50ee9f30ad5ffe3e4cc9d02244c76deec
https://mempool.space/testnet4/tx/fb2eca44409e391b60c5ca61456d0bb50ee9f30ad5ffe3e4cc9d02244c76deec
```

---

## 🆕 What's New

### BIP39 Seed Phrase Support
- **Create wallets with 12 or 24 word seed phrases** - finally, a proper backup!
- **Import existing seed phrases** - restore from any BIP39 compatible wallet
- **BIP84 derivation** - standard `m/84'/0'/0'/0/0` path, works with Electrum, Sparrow, etc.
- **Hardware TRNG entropy** - seed phrases generated using SE050's AIS31 PTG.2 certified RNG

### Lazy Mode 🦥
- Skip seed verification (for testing/degen purposes)
- **Copy all words to clipboard** button
- Auto-clears clipboard after 60 seconds
- Big red "Create Wallet (YOLO)" button

### Improved UI Performance
- **Non-blocking SE050 operations** - UI stays responsive during hardware calls
- **Async fee fetching** - Send dialog opens instantly, fees load in background
- **Async price fetching** - Fiat conversions don't freeze the UI
- **Threaded key checks** - No more UI hangs when checking key slots

---

## ⚠️ IMPORTANT: Backup Options

This wallet now supports **two modes**:

### Option 1: BIP39 Seed Phrase (NEW - Recommended)
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

    SE050ARD seated on headers:
    +-------------------------+
    |      SE050ARD           |
    |   +-------------+       |
    |   |   SE050     |       |
    |   |   (chip)    |       |
    |   +-------------+       |
    +-------------------------+
```

Ensure the SE050ARD is fully seated. The SE050 chip communicates via I2C through the Arduino headers.

### 2. Flash K64F Firmware

The K64F needs NXP's "Virtual COM Port" firmware to bridge USB-to-I2C. The firmware is included in the middleware package:

```bash
# Find the vcom firmware binary in the middleware
ls simw-top/binaries/MCU/K64F/
# Look for: se05x_vcom*.bin
```

To flash:
1. Hold the K64F reset button
2. Connect USB (the DBG port) - K64F appears as mass storage device
3. Drag-drop the vcom .bin file to the K64F drive
4. Release reset button
5. K64F will reboot with new firmware

### 3. Connect K64F to Pi

Connect the K64F's application USB port (not debug port) to your Pi. It should appear as `/dev/ttyACM0`.

```
Pi USB Port  ---->  K64F Application USB Port (not the debug port)
```

Verify:
```bash
ls -la /dev/ttyACM*
# Should show /dev/ttyACM0
```

---

## Software Setup

For complete official instructions, see **NXP AN13027** "EdgeLock SE05x Quick start guide":
https://www.nxp.com/docs/en/application-note/AN13027.pdf

### 1. Download NXP Plug & Trust Middleware

1. Go to NXP website: https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-plug-trust-secure-element-family:SE050

2. Download "EdgeLock SE05x Plug & Trust Middleware" (requires free NXP account)

3. Extract the package to get the `simw-top` directory

### 2. Install ssscli

```bash
cd simw-top/pycli

# Install Python dependencies
pip3 install -r requirements.txt --break-system-packages

# Install ssscli
cd src
python3 setup.py develop --user

# If ssscli not in PATH, add it:
export PATH=$PATH:~/.local/bin

# Verify
ssscli --help
```

### 3. Connect to SE050

```bash
# Open session (do this once, stays open)
ssscli connect se05x vcom /dev/ttyACM0

# Verify connection
ssscli se05x uid
# Should print 18-byte unique ID

# Test TRNG
ssscli se05x getrng
# Should print random hex bytes

# If you see "Session already open", close it first:
ssscli disconnect
ssscli connect se05x vcom /dev/ttyACM0
```

### 4. Install Wallet

```bash
git clone https://github.com/0xdeadbeefnetwork/se050ard_wallet.git
cd se050ard_wallet
chmod +x wallet.py wallet_gui.py

# Optional: QR code support
pip3 install qrcode pillow --break-system-packages
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
- One-click copy addresses
- Send dialog with fee estimation
- **RBF toggle** (Replace-By-Fee) for bumpable transactions
- **CPFP support** (Child-Pays-For-Parent) for stuck incoming transactions
- **RBF replacement** for stuck outgoing transactions
- Message signing
- Transaction history with right-click options
- SE050 verification

### CLI Mode

#### Create Wallet with Seed Phrase

```bash
./wallet.py create              # 12 word seed (default)
./wallet.py create --words 24   # 24 word seed
```

This:
1. Generates entropy using SE050 hardware TRNG
2. Creates BIP39 mnemonic (12 or 24 words)
3. **Displays seed phrase - WRITE IT DOWN!**
4. Derives BIP84 key and writes to SE050

#### Import Existing Seed

```bash
./wallet.py import-seed
# Enter your 12 or 24 word seed phrase when prompted
```

Or provide directly:
```bash
./wallet.py import-seed "word1 word2 word3 ... word12"
```

#### Legacy Init (No Seed)

```bash
./wallet.py init
```

Generates key directly on SE050 with no seed backup. **Not recommended** - use `create` instead.

### Show Addresses

```bash
./wallet.py address

# With QR code for easy mobile scanning
./wallet.py address --qr
```

### Check Balance

```bash
./wallet.py balance

# With fiat conversion (USD, EUR, GBP, etc.)
./wallet.py balance --fiat usd
```

Output:
```
  SegWit:      50,000 sats  (1 UTXOs)
          bc1q6rgrvq509s3l9vpklgzk08nctqymg4977phlde
  Legacy:           0 sats
          1L36yesgc38k8nbkTvp3wk2i6qEG3bPGWm

  ----------------------------------------
  TOTAL:       50,000 sats (0.00050000 BTC)
          ≈ 48.50 USD @ 97,000/USD
          1 spendable UTXOs

  Current fees: 15 sat/vB (fast), 5 sat/vB (slow)
  BTC Price: 97,000 USD
```

### Send Bitcoin

```bash
# Send by satoshis (default)
./wallet.py send bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh 10000

# Send by BTC
./wallet.py send bc1q... 0.0001btc

# Send by USD (auto-converts at current price)
./wallet.py send bc1q... 50usd
./wallet.py send bc1q... $50

# Send by EUR or GBP
./wallet.py send bc1q... 50eur
./wallet.py send bc1q... 50gbp

# Specify fee rate
./wallet.py send bc1q... 50usd --fee 5

# Skip confirmation prompt
./wallet.py send bc1q... 10000 --yes
```

The signing happens entirely on the SE050 - the sighash goes in, a DER signature comes out. Private key never touches the Pi.

### Testnet Mode

```bash
./wallet_gui.py --testnet
./wallet.py --testnet create
./wallet.py --testnet balance
./wallet.py --testnet send tb1q... 10000
```

### Multiple Wallets

Use different key slots:

```bash
./wallet.py --keyid 20000002 create
./wallet.py --keyid 20000002 address
./wallet_gui.py --keyid 20000002
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
- Any BIP39/BIP84 compatible wallet

**⚠️ Electrum Note:** When restoring in Electrum, you MUST click "Options" and check "BIP39 seed" - Electrum uses its own seed format by default.

---

## Security Model

### What's Protected

| Asset | Location | Protection |
|-------|----------|------------|
| Private Key | SE050 chip | Hardware tamper resistance, never exported |
| Key Generation | SE050 TRNG | Hardware random (AIS31 PTG.2 certified) |
| Signing | SE050 | Computed on-chip, key never leaves |
| Seed Phrase | Your paper backup | You're responsible for this! |
| Public Key | Pi filesystem | Not secret |
| Addresses | Pi filesystem | Not secret |

### Attack Scenarios

| Attack | Mitigation |
|--------|------------|
| Pi compromised | Attacker can see addresses/balances but cannot extract key or sign without SE050 |
| USB sniffing | Only sighash (not key) crosses the bus |
| Physical theft of Pi | No key material on Pi (seed phrase not stored) |
| Physical theft of SE050 | Restore from seed phrase to new device |
| Seed phrase stolen | Game over - use metal backup, secure storage |
| Malware requests signatures | Attacker can sign if they control Pi (use dedicated device) |

### What This Doesn't Protect

- **Evil maid attack:** If attacker controls Pi, they can request signatures
- **No display:** No way to verify transaction details on the hardware itself
- **No PIN protection:** SE050 supports this but it's broken on eval boards (see Known Issues)
- **Seed phrase security:** That's on you - store it safely!

---

## Known Issues

### PIN/UserID Authentication Doesn't Work

The SE050 eval board has a pre-provisioned UserID auth object (`0x7DA00001`) with a restrictive policy that blocks authentication. **Do not attempt to use `--auth_type UserID`** - it will create keys you cannot delete.

```bash
# DON'T DO THIS - creates stuck keys
ssscli connect se05x vcom /dev/ttyACM0 --auth_type UserID
ssscli generate ecc 0x20000099 NIST_P256 --policy_name some_policy
# Key is now stuck forever, can't delete it
```

Stuck key slots observed: `0x20000003`, `0x20000004`, `0x20000099`

This is a limitation of the eval board, not the SE050 chip itself.

### I2C Bus is Unencrypted

Communication between K64F and SE050 is plain I2C. The SE050 supports SCP03 encrypted sessions but ssscli's implementation doesn't work with the eval board's auth setup. Not a major concern for most threat models.

---

## Troubleshooting

### "ssscli not found"

```bash
# Check where it installed
which ssscli
pip3 show ssscli

# Add to PATH if needed (usually ~/.local/bin)
export PATH=$PATH:~/.local/bin

# Or run from the pycli/src directory
cd /path/to/simw-top/pycli/src
python3 -m ssscli --help
```

### "Connection failed"

1. Check USB connection (use application port, not debug)
2. Check device exists: `ls /dev/ttyACM*`
3. Check permissions: `sudo chmod 666 /dev/ttyACM0`
4. Re-flash K64F firmware

### "Session already open"

```bash
ssscli disconnect
ssscli connect se05x vcom /dev/ttyACM0
```

### "Key generation failed"

Key slot might be occupied:
```bash
ssscli se05x readidlist  # Check what's there
ssscli erase 20000001    # Only if you want to delete it!
```

### Electrum Shows Wrong Addresses

When restoring in Electrum:
1. Choose "Standard wallet"
2. Choose "I already have a seed"
3. Enter your seed words
4. **Click "Options"**
5. **Check "BIP39 seed"** ← This is critical!
6. Choose "native segwit (p2wpkh)"

If you skip steps 4-5, Electrum uses its own seed format and derives different addresses.

---

## How It Works

### BIP39 Seed Generation

```
SE050 TRNG (AIS31 PTG.2)
         |
         v
   128 or 256 bits entropy
         |
         v
   SHA256 checksum (4 or 8 bits)
         |
         v
   Split into 11-bit chunks
         |
         v
   Map to BIP39 wordlist
         |
         v
   12 or 24 word mnemonic
```

### Key Derivation

```
Mnemonic + "" (empty passphrase)
         |
         v
   PBKDF2-HMAC-SHA512 (2048 rounds)
         |
         v
   512-bit seed
         |
         v
   BIP32 master key
         |
         v
   m/84'/0'/0'/0/0  (BIP84 path)
         |
         v
   secp256k1 private key
         |
         v
   Written to SE050
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
| **BIP39 seed phrases (12/24 words)** | ✅ **NEW** |
| **Import existing seeds** | ✅ **NEW** |
| **Lazy mode (skip verification)** | ✅ **NEW** |
| **Copy seed to clipboard** | ✅ **NEW** |
| **Non-blocking UI** | ✅ **NEW** |
| Key generation (secp256k1) | ✅ Working |
| P2WPKH (Native SegWit) | ✅ Working |
| P2PKH (Legacy) | ✅ Working |
| Mainnet | ✅ Working |
| Testnet4 | ✅ Tested |
| Fee estimation | ✅ Working |
| Fiat price conversion | ✅ Working |
| Send in BTC/USD/EUR/GBP | ✅ Working |
| QR code display | ✅ Working |
| Message signing | ✅ Working |
| Transaction history | ✅ Working |
| SE050 verification | ✅ Working |
| Multiple wallets | ✅ Via --keyid |
| BIP-62 low-S signatures | ✅ Normalized |
| Transaction broadcast | ✅ Via mempool.space |
| Tkinter GUI | ✅ Working |
| RBF (Replace-By-Fee) | ✅ Working |
| CPFP (Child-Pays-For-Parent) | ✅ Working |
| P2SH-P2WPKH (Wrapped SegWit) | ❌ Not implemented |
| Multisig | ❌ Not implemented |
| Hardware PIN/auth | ❌ Broken on eval board |

---

## File Locations

```
~/.se050-wallet/
    pubkey_20000001.der    # DER-encoded public key from SE050
    pubkey_20000001.pem    # PEM-encoded public key  
    wallet_20000001.json   # Metadata (addresses, created timestamp)
```

---

## Dependencies

**Required:**
- Python 3.7+
- ssscli (NXP Plug & Trust Middleware)

**Optional:**
- `qrcode` - QR code display
- `pillow` - Image support for GUI QR codes

```bash
pip3 install qrcode pillow --break-system-packages
```

---

## License

MIT

## Author

_SiCk @ afflicted.sh

## Contributing

Issues and PRs welcome. This is experimental software - use at your own risk.

## Disclaimer

This is experimental software. While it now supports seed phrase backups, you are responsible for securing your seed phrase. The author is not responsible for any loss of funds.

---

*"Not your keys, not your coins. Your keys in a secure element, backed up on paper, definitely your coins."*
