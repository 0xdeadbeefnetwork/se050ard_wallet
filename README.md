# SE050ARD Bitcoin Wallet

A Bitcoin hardware wallet using the NXP SE050 secure element. Private keys are generated inside tamper-resistant silicon and **never leave the chip** - all signing happens on-device.

**Official NXP Setup Guide:** [AN13027 - EdgeLock SE05x Quick start guide](https://www.nxp.com/docs/en/application-note/AN13027.pdf)

**Tested and working on Bitcoin testnet4:**
```
TXID: fb2eca44409e391b60c5ca61456d0bb50ee9f30ad5ffe3e4cc9d02244c76deec
https://mempool.space/testnet4/tx/fb2eca44409e391b60c5ca61456d0bb50ee9f30ad5ffe3e4cc9d02244c76deec
```

---

## ⚠️ IMPORTANT: No Seed Phrase - By Design

**This wallet does NOT generate a BIP-39 seed phrase (12/24 words).**

Unlike software wallets and most hardware wallets (Ledger, Trezor), the SE050 generates keys **inside the chip** using a hardware true random number generator (TRNG). The private key:

- Is generated on-chip and stored in tamper-resistant silicon
- **Cannot be exported** - there is no command to extract it
- **Cannot be backed up** to paper or another device
- **Cannot be recovered** if the SE050 is lost/destroyed

### Why No Seed Phrase?

| Traditional Wallet | SE050 Wallet |
|-------------------|--------------|
| Seed phrase can be written down | No seed phrase exists |
| Seed phrase can be stolen/phished | Nothing to steal |
| Seed phrase can be recovered | Hardware is the only backup |
| Software generates keys | Hardware generates keys |

**This is a security tradeoff:**
- ✅ **Pro:** No seed words to leak, phish, or extract via malware
- ❌ **Con:** Lose the SE050 chip = lose funds forever

**Recommendation:** Use this for learning, small amounts, or as part of a multisig setup. For significant funds, use established hardware wallets with seed backup capability.

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
ssscli connect se05x t1oi2c none

# Verify connection
ssscli se05x uid
# Should print 18-byte unique ID

# Test TRNG
ssscli se05x getrng
# Should print random hex bytes

# If you see "Session already open", close it first:
ssscli disconnect
ssscli connect se05x t1oi2c none
```

### 4. Install Wallet

```bash
git clone https://github.com/AffictedIntelligence/se050ard_wallet.git
cd se050ard_wallet
chmod +x wallet.py
```

---

## Usage

### Initialize Wallet

```bash
./wallet.py init
```

This:
1. Connects to SE050
2. Generates secp256k1 keypair on-chip using hardware TRNG
3. Exports public key (private key stays in SE050)
4. Derives Bitcoin addresses

Output:
```
============================================================
WALLET CREATED SUCCESSFULLY
============================================================

Key ID:     0x20000001
Network:    mainnet
Pubkey:     037e720714fa3b8e4b5ab32272724d48048322f114f6fef27776d53c93aeabae18

RECEIVE ADDRESSES:
  Legacy:  1L36yesgc38k8nbkTvp3wk2i6qEG3bPGWm
  SegWit:  bc1q6rgrvq509s3l9vpklgzk08nctqymg4977phlde

IMPORTANT:
  - Private key is stored ONLY in SE050 secure element
  - Back up your Key ID (0x20000001) and SE050 device
  - Loss of SE050 = Loss of funds!
============================================================
```

### Show Addresses

```bash
./wallet.py address
```

### Check Balance

```bash
./wallet.py balance
```

Uses mempool.space API to check both Legacy and SegWit addresses. Also displays current network fee estimates.

### Send Bitcoin

```bash
# Send 10000 sats with default fee (10 sat/vB)
./wallet.py send bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh 10000

# Specify fee rate
./wallet.py send bc1q... 50000 --fee 5

# Skip confirmation prompt
./wallet.py send bc1q... 50000 --yes
```

The signing happens entirely on the SE050 - the sighash goes in, a DER signature comes out. Private key never touches the Pi.

### Testnet Mode

```bash
./wallet.py --testnet init
./wallet.py --testnet balance
./wallet.py --testnet send tb1q... 10000
```

### Multiple Wallets

Use different key slots:

```bash
./wallet.py --keyid 20000002 init
./wallet.py --keyid 20000002 address
```

### Export Public Key

```bash
./wallet.py export
```

Exports public key in hex and PEM format. **Never exports private key** (because it can't).

### Wipe Wallet

```bash
./wallet.py wipe
```

Deletes key from SE050 and local files. **IRREVERSIBLE** - funds will be lost!

---

## Verifying the SE050 is Really Signing

Don't trust - verify! Here's how to confirm the SE050 hardware is actually being used:

### 1. Verify Public Key Matches SE050

```bash
# Export fresh copy from SE050
ssscli connect se05x t1oi2c none
ssscli get ecc pub 20000001 /tmp/verify_pubkey.der --format DER

# Compare with wallet's stored copy
diff /tmp/verify_pubkey.der ~/.se050-wallet/pubkey_20000001.der
echo $?
# Output: 0 (files are identical)

# If different, something is wrong!
```

### 2. Examine the Public Key

```bash
# View raw DER bytes
xxd ~/.se050-wallet/pubkey_20000001.der

# Extract and display with OpenSSL
openssl ec -pubin -inform DER -in ~/.se050-wallet/pubkey_20000001.der -text -noout

# You should see:
#   ASN1 OID: secp256k1
#   pub: 04:xx:xx:xx... (65 bytes uncompressed)
```

### 3. Test Signature Generation

```bash
# Create test message
echo -n "test message for SE050" > /tmp/test_msg.bin

# Sign with SE050
ssscli sign 20000001 /tmp/test_msg.bin /tmp/test_sig.der --hashalgo SHA256

# View signature (should be valid DER: 30 xx 02 xx ... 02 xx ...)
xxd /tmp/test_sig.der

# Verify structure: 0x30 = SEQUENCE, 0x02 = INTEGER (for r and s values)
```

### 4. Verify Signature with OpenSSL

```bash
# Hash the message (SHA256)
openssl dgst -sha256 -binary /tmp/test_msg.bin > /tmp/test_hash.bin

# Verify signature against public key
openssl pkeyutl -verify \
    -pubin -inkey ~/.se050-wallet/pubkey_20000001.pem \
    -in /tmp/test_hash.bin \
    -sigfile /tmp/test_sig.der

# Output should be: "Signature Verified Successfully"
```

### 5. Confirm Key Cannot Be Extracted

```bash
# Try to get private key (should fail)
ssscli get ecc pair 20000001 /tmp/keypair.der --format DER
# Error: Operation not permitted / Access denied

# This proves the private key is locked inside the SE050
```

---

## Security Model

### What's Protected

| Asset | Location | Protection |
|-------|----------|------------|
| Private Key | SE050 chip | Hardware tamper resistance, never exported |
| Key Generation | SE050 TRNG | Hardware random, not PRNG |
| Signing | SE050 | Computed on-chip, key never leaves |
| Public Key | Pi filesystem | Not secret |
| Addresses | Pi filesystem | Not secret |

### Attack Scenarios

| Attack | Mitigation |
|--------|------------|
| Pi compromised | Attacker can see addresses/balances but cannot extract key or sign without SE050 |
| USB sniffing | Only sighash (not key) crosses the bus |
| Physical theft of Pi | No key material on Pi |
| Physical theft of SE050 | Tamper mesh, limited PIN attempts (if configured) |
| Malware requests signatures | Attacker can sign arbitrary messages if they control Pi |

### What This Doesn't Protect

- **Evil maid attack:** If attacker controls Pi, they can request signatures for arbitrary transactions
- **No display:** No way to verify transaction details on the hardware itself
- **No PIN protection:** This implementation doesn't use SE050's authentication features (yet)
- **No seed backup:** Lose the chip = lose funds

For high-value storage, use a proper air-gapped setup or commercial hardware wallet with display.

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
ssscli connect se05x t1oi2c none
```

### "Key generation failed"

Key slot might be occupied:
```bash
ssscli erase 20000001
```

Then try init again.

### Wrong Addresses After Re-init

Each `init` generates a **NEW** keypair. Old addresses are gone forever. The SE050 doesn't store key history.

### Signature Verification Failed

1. Check you're using the correct key ID
2. Verify public key matches: `ssscli get ecc pub <keyid> /tmp/check.der`
3. Ensure BIP-62 low-S normalization is working (wallet.py handles this)

---

## How It Works

### Key Generation

```bash
ssscli generate ecc 20000001 Secp256k1
```

SE050 uses its hardware TRNG to generate a random 256-bit private key, then computes the public key. Both are stored in non-volatile memory at key slot 0x20000001. The private key **cannot be read out**.

### Address Derivation (on Pi)

```
Compressed Public Key (33 bytes)
         |
         v
      SHA256
         |
         v
     RIPEMD160
         |
         v
   20-byte pubkey hash
         |
    +----+----+
    |         |
    v         v
Base58Check  Bech32
(Legacy)    (SegWit)
```

### Transaction Signing Flow

```
   Pi                          SE050
    |                            |
    | 1. Build unsigned TX       |
    | 2. Compute BIP-143 preimage|
    | 3. SHA256(preimage)        |
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

### Why Single-SHA256 to SE050?

The `ssscli sign` command always hashes its input before signing (no raw mode). Bitcoin needs double-SHA256 of the sighash preimage. So we:

1. Compute `SHA256(preimage)` on the Pi
2. Send that to SE050 with `--hashalgo SHA256`
3. SE050 computes `SHA256(our_input)` = `SHA256(SHA256(preimage))` = correct sighash
4. SE050 signs the sighash

### Low-S Signature Normalization

Bitcoin requires BIP-62 compliant signatures where `S <= curve_order/2`. The SE050 produces valid ECDSA signatures but doesn't enforce low-S. We normalize after receiving:

```python
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_ORDER = SECP256K1_ORDER // 2

if s > SECP256K1_HALF_ORDER:
    s = SECP256K1_ORDER - s
```

---

## File Locations

```
~/.se050-wallet/
    pubkey_20000001.der    # DER-encoded public key from SE050
    pubkey_20000001.pem    # PEM-encoded public key  
    wallet_20000001.json   # Metadata (addresses, created timestamp)
    tx_*.hex               # Failed transaction hex (for debugging)
```

---

## Fee Estimation

The wallet fetches fee estimates from mempool.space API:

```bash
./wallet.py balance
# Shows: Current fees: 15 sat/vB (fast), 5 sat/vB (slow)
```

When sending:
- Default fee: 10 sat/vB
- Override with `--fee` flag: `./wallet.py send <addr> <amt> --fee 20`
- Wallet estimates vsize based on input count

Future improvements could include:
- Smarter coin selection (minimize inputs)
- RBF (Replace-By-Fee) support
- CPFP (Child-Pays-For-Parent)

---

## Supported Features

| Feature | Status |
|---------|--------|
| Key generation (secp256k1) | ✅ Working |
| P2WPKH (Native SegWit) | ✅ Working |
| P2PKH (Legacy) | ✅ Working |
| Mainnet | ✅ Working |
| Testnet4 | ✅ Tested |
| Fee estimation | ✅ Basic |
| Multiple wallets | ✅ Via --keyid |
| BIP-62 low-S signatures | ✅ Normalized |
| Transaction broadcast | ✅ Via mempool.space |
| P2SH-P2WPKH (Wrapped SegWit) | ❌ Not implemented |
| Multisig | ❌ Not implemented |
| RBF | ❌ Not implemented |
| Hardware PIN/auth | ❌ Not implemented |

---

## Dependencies

- Python 3.7+
- ssscli (NXP Plug & Trust Middleware)
- No other Python packages required (uses stdlib only)

---

## License

MIT

## Author

Trevor / Afflicted Intelligence LLC

## Repository

https://github.com/AffictedIntelligence/se050ard_wallet

## Contributing

Issues and PRs welcome. This is experimental software - use at your own risk.

## Disclaimer

This is experimental software for educational purposes. There is **NO seed phrase backup** - if you lose the SE050, you lose your funds. Do not use with funds you cannot afford to lose. The author is not responsible for any loss of funds.
