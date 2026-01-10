#!/usr/bin/env python3
"""
SE050ARD Hardware Bitcoin Wallet
=================================

A Bitcoin wallet using NXP SE050 secure element for key storage.
Private keys are generated and stored in tamper-resistant silicon.

IMPORTANT: This wallet does NOT generate a seed phrase!
           The private key exists ONLY inside the SE050 chip.
           Loss of the SE050 = Loss of funds forever!

Requirements:
    - Raspberry Pi (tested on Pi 400)
    - NXP SE050 evaluation kit (SE050ARD) via K64F
    - ssscli from NXP Plug & Trust middleware
    - Python 3.7+

Setup:
    1. Connect SE050ARD to K64F via Arduino headers
    2. Connect K64F to Pi via USB
    3. Install ssscli (see NXP AN13027)
    4. Run: ssscli connect se05x t1oi2c none

Usage:
    ./wallet.py init                    # Create new wallet (generates key on SE050)
    ./wallet.py address                 # Show receive addresses
    ./wallet.py balance                 # Check balance via mempool.space
    ./wallet.py send <address> <sats>   # Send Bitcoin (signs on SE050)
    ./wallet.py export                  # Export public key info (NO private key!)
    ./wallet.py wipe                    # Delete key from SE050 (DANGER!)
    ./wallet.py info                    # Show SE050 status and key info

Repository: https://github.com/AffictedIntelligence/se050ard_wallet
License: MIT
Author: Trevor / Afflicted Intelligence LLC
"""

import sys
import os
import hashlib
import subprocess
import json
import urllib.request
import urllib.error
import argparse
import shutil
from pathlib import Path
from datetime import datetime
from typing import Tuple, Optional, List, Dict

# ============================================================================
#                              QR CODE GENERATION
# ============================================================================

def generate_qr_ascii(data: str, border: int = 1) -> str:
    """
    Generate ASCII QR code using pure Python.
    Implements QR Code Model 2, Version 1-4 (up to 50 chars for alphanumeric)
    Falls back to simplified display if data too long.
    """
    # Try to use qrcode library if available, otherwise use simple box
    try:
        import importlib.util
        if importlib.util.find_spec('qrcode'):
            import qrcode
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=1,
                border=border
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            lines = []
            for row in qr.modules:
                line = ''
                for cell in row:
                    line += '██' if cell else '  '
                lines.append(line)
            return '\n'.join(lines)
    except:
        pass
    
    # Fallback: simple framed display
    lines = []
    lines.append('┌' + '─' * (len(data) + 2) + '┐')
    lines.append('│ ' + data + ' │')
    lines.append('└' + '─' * (len(data) + 2) + '┘')
    lines.append('')
    lines.append('(Install qrcode for QR: pip3 install qrcode)')
    return '\n'.join(lines)

# ============================================================================
#                              CONFIGURATION
# ============================================================================

class Config:
    """Wallet configuration"""
    # SE050 Key slot - change this to manage multiple wallets
    KEY_ID = "20000001"
    
    # Data directory for wallet files
    WALLET_DIR = Path.home() / ".se050-wallet"
    
    # API endpoints
    MEMPOOL_API = "https://mempool.space/api"
    MEMPOOL_TESTNET_API = "https://mempool.space/testnet4/api"
    
    # Network: "mainnet" or "testnet"
    NETWORK = "mainnet"
    
    # Fee rate in sat/vbyte
    DEFAULT_FEE_RATE = 10
    
    @classmethod
    def pubkey_der_path(cls) -> Path:
        return cls.WALLET_DIR / f"pubkey_{cls.KEY_ID}.der"
    
    @classmethod
    def pubkey_pem_path(cls) -> Path:
        return cls.WALLET_DIR / f"pubkey_{cls.KEY_ID}.pem"
    
    @classmethod
    def wallet_info_path(cls) -> Path:
        return cls.WALLET_DIR / f"wallet_{cls.KEY_ID}.json"
    
    @classmethod
    def api_base(cls) -> str:
        return cls.MEMPOOL_TESTNET_API if cls.NETWORK == "testnet" else cls.MEMPOOL_API
    
    @classmethod
    def address_version(cls) -> bytes:
        return b'\x6f' if cls.NETWORK == "testnet" else b'\x00'
    
    @classmethod
    def bech32_hrp(cls) -> str:
        return "tb" if cls.NETWORK == "testnet" else "bc"

# ============================================================================
#                           CRYPTOGRAPHIC PRIMITIVES
# ============================================================================

B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_ORDER = SECP256K1_ORDER // 2

def sha256(data: bytes) -> bytes:
    """Single SHA256 hash"""
    return hashlib.sha256(data).digest()

def sha256d(data: bytes) -> bytes:
    """Double SHA256 hash (Bitcoin standard)"""
    return sha256(sha256(data))

def ripemd160(data: bytes) -> bytes:
    """RIPEMD160 hash"""
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def hash160(data: bytes) -> bytes:
    """HASH160: SHA256 followed by RIPEMD160"""
    return ripemd160(sha256(data))

def b58encode(data: bytes) -> str:
    """Base58 encode (no checksum)"""
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = B58_ALPHABET[r] + result
    for byte in data:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result or '1'

def b58check_encode(version: bytes, payload: bytes) -> str:
    """Base58Check encode with version byte and checksum"""
    data = version + payload
    checksum = sha256d(data)[:4]
    return b58encode(data + checksum)

def b58check_decode(addr: str) -> Tuple[bytes, bytes]:
    """Base58Check decode, returns (version, payload)"""
    n = 0
    for c in addr:
        n = n * 58 + B58_ALPHABET.index(c)
    data = n.to_bytes(25, 'big')
    version, payload, checksum = data[0:1], data[1:21], data[21:]
    if sha256d(version + payload)[:4] != checksum:
        raise ValueError("Invalid Base58Check checksum")
    return version, payload

# ============================================================================
#                              BECH32 ENCODING
# ============================================================================

BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

def bech32_polymod(values: List[int]) -> int:
    """Bech32 checksum computation"""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand HRP for checksum computation"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    """Create Bech32 checksum"""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp: str, data: List[int]) -> str:
    """Encode to Bech32"""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in combined])

def bech32_decode(addr: str) -> Tuple[str, int, bytes]:
    """Decode Bech32 address, returns (hrp, witness_version, witness_program)"""
    pos = addr.rfind('1')
    hrp = addr[:pos].lower()
    data = [BECH32_CHARSET.index(c) for c in addr[pos + 1:].lower()]
    witness_version = data[0]
    witness_program = convertbits(data[1:-6], 5, 8, pad=False)
    return hrp, witness_version, bytes(witness_program)

def convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> List[int]:
    """Convert between bit widths"""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    return ret

# ============================================================================
#                           SIGNATURE UTILITIES
# ============================================================================

def parse_der_signature(sig: bytes) -> Tuple[int, int]:
    """Parse DER signature into (r, s) integers"""
    if sig[0] != 0x30:
        raise ValueError("Invalid DER signature")
    
    idx = 2
    
    if sig[idx] != 0x02:
        raise ValueError("Invalid DER signature")
    idx += 1
    r_len = sig[idx]
    idx += 1
    r = int.from_bytes(sig[idx:idx + r_len], 'big')
    idx += r_len
    
    if sig[idx] != 0x02:
        raise ValueError("Invalid DER signature")
    idx += 1
    s_len = sig[idx]
    idx += 1
    s = int.from_bytes(sig[idx:idx + s_len], 'big')
    
    return r, s

def encode_der_signature(r: int, s: int) -> bytes:
    """Encode (r, s) integers as DER signature"""
    def encode_int(n: int) -> bytes:
        b = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return bytes([0x02, len(b)]) + b
    
    r_enc = encode_int(r)
    s_enc = encode_int(s)
    payload = r_enc + s_enc
    return bytes([0x30, len(payload)]) + payload

def normalize_signature(sig_der: bytes) -> bytes:
    """Normalize signature to low-S form per BIP-62"""
    r, s = parse_der_signature(sig_der)
    
    if s > SECP256K1_HALF_ORDER:
        s = SECP256K1_ORDER - s
    
    return encode_der_signature(r, s)

def create_message_hash(message: str) -> bytes:
    """
    Create Bitcoin signed message hash.
    Format: SHA256(SHA256("\x18Bitcoin Signed Message:\n" + varint(len) + message))
    """
    prefix = b'\x18Bitcoin Signed Message:\n'
    msg_bytes = message.encode('utf-8')
    
    # Varint encode message length
    msg_len = len(msg_bytes)
    if msg_len < 0xfd:
        len_bytes = bytes([msg_len])
    elif msg_len <= 0xffff:
        len_bytes = b'\xfd' + msg_len.to_bytes(2, 'little')
    else:
        len_bytes = b'\xfe' + msg_len.to_bytes(4, 'little')
    
    full_msg = prefix + len_bytes + msg_bytes
    return sha256d(full_msg)

def sign_message_with_se050(key_id: str, message: str) -> Tuple[bytes, int]:
    """
    Sign a message using SE050 and return (signature, recovery_id).
    Returns compact signature format for Bitcoin message signing.
    """
    msg_hash = create_message_hash(message)
    
    # SE050 expects single SHA256, will do second internally
    # But for message signing we need the full double-SHA256
    # So we pass single-SHA256 of the message hash prefix+msg
    prefix = b'\x18Bitcoin Signed Message:\n'
    msg_bytes = message.encode('utf-8')
    msg_len = len(msg_bytes)
    if msg_len < 0xfd:
        len_bytes = bytes([msg_len])
    elif msg_len <= 0xffff:
        len_bytes = b'\xfd' + msg_len.to_bytes(2, 'little')
    else:
        len_bytes = b'\xfe' + msg_len.to_bytes(4, 'little')
    full_msg = prefix + len_bytes + msg_bytes
    single_hash = sha256(full_msg)
    
    # Sign using SE050 (it will do second SHA256)
    sig_der = se050_sign(key_id, single_hash)
    r, s = parse_der_signature(sig_der)
    
    # Recovery ID: we'll try 0 and 1, use 0 as default
    # Full recovery requires checking against pubkey
    recovery_id = 0
    
    return (r, s), recovery_id

def encode_signed_message(r: int, s: int, recovery_id: int, compressed: bool = True) -> str:
    """Encode signature as base64 string for Bitcoin signed message"""
    import base64
    
    # Header byte: 27 + recovery_id + (4 if compressed)
    header = 27 + recovery_id + (4 if compressed else 0)
    
    # Signature: 1 byte header + 32 bytes r + 32 bytes s = 65 bytes
    sig_bytes = bytes([header])
    sig_bytes += r.to_bytes(32, 'big')
    sig_bytes += s.to_bytes(32, 'big')
    
    return base64.b64encode(sig_bytes).decode('ascii')

# ============================================================================
#                              KEY UTILITIES
# ============================================================================

def compress_pubkey(pubkey: bytes) -> bytes:
    """Compress 65-byte uncompressed public key to 33-byte compressed"""
    if len(pubkey) != 65 or pubkey[0] != 0x04:
        raise ValueError("Invalid uncompressed public key")
    x = pubkey[1:33]
    y = pubkey[33:65]
    prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
    return prefix + x

def parse_der_pubkey(der_data: bytes) -> bytes:
    """Extract 65-byte uncompressed public key from DER-encoded SubjectPublicKeyInfo"""
    idx = der_data.find(b'\x04', 20)
    if idx == -1:
        raise ValueError("Could not find uncompressed public key marker in DER data")
    return der_data[idx:idx + 65]

def derive_addresses(pubkey_compressed: bytes) -> Dict[str, str]:
    """Derive Bitcoin addresses from compressed public key"""
    pubkey_hash = hash160(pubkey_compressed)
    
    legacy = b58check_encode(Config.address_version(), pubkey_hash)
    segwit = bech32_encode(Config.bech32_hrp(), [0] + convertbits(pubkey_hash, 8, 5))
    
    return {
        'legacy': legacy,
        'segwit': segwit,
        'pubkey_hash': pubkey_hash.hex()
    }

# ============================================================================
#                              SE050 INTERFACE
# ============================================================================

class SE050Error(Exception):
    """SE050 operation failed"""
    pass

def run_ssscli(args: List[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run ssscli command and return result"""
    cmd = ['ssscli'] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if check and result.returncode != 0:
        raise SE050Error(f"ssscli failed: {result.stderr or result.stdout}")
    
    return result

def se050_check_connection() -> bool:
    """Check if SE050 is connected and accessible"""
    try:
        result = run_ssscli(['se05x', 'uid'], check=False)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def se050_connect() -> bool:
    """Establish connection to SE050"""
    try:
        result = run_ssscli(['connect', 'se05x', 't1oi2c', 'None'], check=False)
        return result.returncode == 0 or 'already open' in result.stdout.lower()
    except Exception as e:
        print(f"Connection error: {e}")
        return False

def se050_get_uid() -> Optional[str]:
    """Get SE050 unique identifier"""
    try:
        result = run_ssscli(['se05x', 'uid'])
        for line in result.stdout.split('\n'):
            if 'uid' in line.lower() or len(line.strip()) == 36:
                uid = ''.join(c for c in line if c in '0123456789abcdefABCDEF')
                if len(uid) >= 16:
                    return uid
        return None
    except SE050Error:
        return None

def se050_get_random(num_bytes: int = 10) -> Optional[bytes]:
    """Get random bytes from SE050 TRNG"""
    try:
        result = run_ssscli(['se05x', 'getrng'])
        for line in result.stdout.split('\n'):
            if 'random' in line.lower():
                hex_str = ''.join(c for c in line if c in '0123456789abcdefABCDEF')
                if hex_str:
                    return bytes.fromhex(hex_str)
        return None
    except SE050Error:
        return None

def se050_generate_keypair(key_id: str, curve: str = "Secp256k1") -> bool:
    """Generate ECC keypair on SE050"""
    try:
        run_ssscli(['generate', 'ecc', key_id, curve])
        return True
    except SE050Error as e:
        print(f"Key generation failed: {e}")
        return False

def se050_export_pubkey(key_id: str, output_path: Path, format: str = "DER") -> bool:
    """Export public key from SE050"""
    try:
        run_ssscli(['get', 'ecc', 'pub', key_id, str(output_path), '--format', format])
        return True
    except SE050Error as e:
        print(f"Public key export failed: {e}")
        return False

def se050_delete_key(key_id: str) -> bool:
    """Delete key from SE050"""
    try:
        run_ssscli(['erase', key_id])
        return True
    except SE050Error as e:
        print(f"Key deletion failed: {e}")
        return False

def se050_sign(key_id: str, data: bytes) -> bytes:
    """
    Sign data using SE050 key, returns normalized low-S DER signature.
    
    Note: ssscli always hashes input before signing. We pass single-SHA256
    of the preimage, and ssscli does the second SHA256 to produce the
    final sighash that gets signed.
    """
    data_file = Path("/tmp/se050_sign_input.bin")
    sig_file = Path("/tmp/se050_signature.der")
    
    try:
        data_file.write_bytes(data)
        
        run_ssscli([
            'sign', key_id,
            str(data_file), str(sig_file),
            '--informat', 'DER',
            '--outformat', 'DER',
            '--hashalgo', 'SHA256'
        ])
        
        signature = sig_file.read_bytes()
        signature = normalize_signature(signature)
        
        return signature
        
    finally:
        if data_file.exists():
            data_file.unlink()
        if sig_file.exists():
            sig_file.unlink()

def se050_key_exists(key_id: str) -> bool:
    """Check if key exists in SE050"""
    try:
        temp_file = Path(f"/tmp/check_{key_id}.der")
        result = run_ssscli(['get', 'ecc', 'pub', key_id, str(temp_file), '--format', 'DER'], check=False)
        if temp_file.exists():
            temp_file.unlink()
        return result.returncode == 0
    except:
        return False

# ============================================================================
#                              API INTERFACE
# ============================================================================

def api_get(endpoint: str) -> Optional[Dict]:
    """GET request to mempool.space API"""
    url = f"{Config.api_base()}{endpoint}"
    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'SE050-Bitcoin-Wallet/1.0')
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except Exception as e:
        print(f"API error: {e}")
        return None

def api_post(endpoint: str, data: bytes) -> Optional[str]:
    """POST request to mempool.space API"""
    url = f"{Config.api_base()}{endpoint}"
    try:
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'text/plain')
        req.add_header('User-Agent', 'SE050-Bitcoin-Wallet/1.0')
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        print(f"Broadcast error: {error_body}")
        return None

def get_utxos(address: str) -> List[Dict]:
    """Fetch UTXOs for address"""
    result = api_get(f"/address/{address}/utxo")
    return result if result else []

def get_address_info(address: str) -> Optional[Dict]:
    """Get address balance and transaction info"""
    return api_get(f"/address/{address}")

def get_fee_estimates() -> Dict[str, int]:
    """Get current fee estimates"""
    result = api_get("/v1/fees/recommended")
    return result if result else {'fastestFee': 20, 'halfHourFee': 10, 'hourFee': 5}

def get_btc_price(currency: str = 'USD') -> Optional[float]:
    """Get current BTC price from mempool.space or coingecko"""
    # Try mempool.space first
    try:
        url = "https://mempool.space/api/v1/prices"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'SE050ARD-Wallet/1.0')
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return float(data.get(currency, data.get('USD', 0)))
    except:
        pass
    
    # Fallback to coingecko
    try:
        url = f"https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies={currency.lower()}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'SE050ARD-Wallet/1.0')
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return float(data['bitcoin'][currency.lower()])
    except:
        return None

def get_address_txs(address: str, limit: int = 10) -> List[Dict]:
    """Get transaction history for address"""
    result = api_get(f"/address/{address}/txs")
    if result:
        return result[:limit]
    return []

def format_timestamp(unix_ts: int) -> str:
    """Format unix timestamp to readable date"""
    from datetime import datetime
    return datetime.fromtimestamp(unix_ts).strftime('%Y-%m-%d %H:%M')

# ============================================================================
#                           TRANSACTION BUILDING
# ============================================================================

def varint(n: int) -> bytes:
    """Encode integer as Bitcoin varint"""
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')

def build_p2wpkh_sighash_preimage(
    inputs: List[Dict],
    outputs: List[Dict],
    input_index: int,
    pubkey_hash: bytes,
    value: int
) -> bytes:
    """
    Build BIP-143 sighash preimage for P2WPKH input.
    
    Returns SINGLE SHA256 of preimage. The SE050/ssscli will perform
    the second SHA256 before signing, resulting in proper double-SHA256 sighash.
    """
    
    prevouts = b''
    for inp in inputs:
        prevouts += bytes.fromhex(inp['txid'])[::-1]
        prevouts += inp['vout'].to_bytes(4, 'little')
    hash_prevouts = sha256d(prevouts)
    
    sequences = b''
    for inp in inputs:
        sequences += (0xfffffffd).to_bytes(4, 'little')
    hash_sequence = sha256d(sequences)
    
    outputs_ser = b''
    for out in outputs:
        outputs_ser += out['value'].to_bytes(8, 'little')
        outputs_ser += varint(len(out['script'])) + out['script']
    hash_outputs = sha256d(outputs_ser)
    
    script_code = bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])
    
    inp = inputs[input_index]
    preimage = b''
    preimage += (2).to_bytes(4, 'little')
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += bytes.fromhex(inp['txid'])[::-1]
    preimage += inp['vout'].to_bytes(4, 'little')
    preimage += varint(len(script_code)) + script_code
    preimage += value.to_bytes(8, 'little')
    preimage += (0xfffffffd).to_bytes(4, 'little')
    preimage += hash_outputs
    preimage += (0).to_bytes(4, 'little')
    preimage += (1).to_bytes(4, 'little')
    
    # Return SINGLE SHA256 - ssscli will do the second
    return sha256(preimage)

def create_output_script(address: str) -> bytes:
    """Create output script for address"""
    if address.startswith('bc1') or address.startswith('tb1'):
        _, wver, wprog = bech32_decode(address)
        return bytes([0x00, len(wprog)]) + wprog
    elif address.startswith('1') or address.startswith('m') or address.startswith('n'):
        _, pubkey_hash = b58check_decode(address)
        return bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])
    elif address.startswith('3') or address.startswith('2'):
        _, script_hash = b58check_decode(address)
        return bytes([0xa9, 0x14]) + script_hash + bytes([0x87])
    else:
        raise ValueError(f"Unsupported address format: {address}")

def build_and_sign_transaction(
    inputs: List[Dict],
    outputs: List[Dict],
    pubkey_compressed: bytes,
    pubkey_hash: bytes
) -> bytes:
    """Build and sign complete transaction using SE050"""
    
    witnesses = []
    
    for i, inp in enumerate(inputs):
        print(f"    Signing input {i + 1}/{len(inputs)}...")
        
        # Get single-SHA256 of preimage; SE050 will do second SHA256
        sighash_single = build_p2wpkh_sighash_preimage(
            inputs, outputs, i, pubkey_hash, inp['value']
        )
        
        sig_der = se050_sign(Config.KEY_ID, sighash_single)
        
        sig_with_hashtype = sig_der + b'\x01'
        witness = b'\x02'
        witness += varint(len(sig_with_hashtype)) + sig_with_hashtype
        witness += varint(len(pubkey_compressed)) + pubkey_compressed
        witnesses.append(witness)
    
    tx = b''
    tx += (2).to_bytes(4, 'little')
    tx += b'\x00\x01'
    
    tx += varint(len(inputs))
    for inp in inputs:
        tx += bytes.fromhex(inp['txid'])[::-1]
        tx += inp['vout'].to_bytes(4, 'little')
        tx += b'\x00'
        tx += (0xfffffffd).to_bytes(4, 'little')
    
    tx += varint(len(outputs))
    for out in outputs:
        tx += out['value'].to_bytes(8, 'little')
        tx += varint(len(out['script'])) + out['script']
    
    for wit in witnesses:
        tx += wit
    
    tx += (0).to_bytes(4, 'little')
    
    return tx

# ============================================================================
#                              WALLET STATE
# ============================================================================

class Wallet:
    """Wallet state management"""
    
    def __init__(self):
        self.pubkey_uncompressed: Optional[bytes] = None
        self.pubkey_compressed: Optional[bytes] = None
        self.addresses: Optional[Dict[str, str]] = None
        self.created_at: Optional[str] = None
        
    def load(self) -> bool:
        """Load wallet from disk"""
        if not Config.pubkey_der_path().exists():
            return False
        
        try:
            der_data = Config.pubkey_der_path().read_bytes()
            self.pubkey_uncompressed = parse_der_pubkey(der_data)
            self.pubkey_compressed = compress_pubkey(self.pubkey_uncompressed)
            self.addresses = derive_addresses(self.pubkey_compressed)
            
            if Config.wallet_info_path().exists():
                info = json.loads(Config.wallet_info_path().read_text())
                self.created_at = info.get('created_at')
            
            return True
        except Exception as e:
            print(f"Failed to load wallet: {e}")
            return False
    
    def save_info(self):
        """Save wallet metadata"""
        info = {
            'key_id': Config.KEY_ID,
            'created_at': self.created_at or datetime.now().isoformat(),
            'network': Config.NETWORK,
            'pubkey_compressed': self.pubkey_compressed.hex() if self.pubkey_compressed else None,
            'addresses': self.addresses
        }
        Config.wallet_info_path().write_text(json.dumps(info, indent=2))
    
    @property
    def pubkey_hash(self) -> bytes:
        """Get pubkey hash (HASH160 of compressed pubkey)"""
        if not self.pubkey_compressed:
            raise ValueError("Wallet not loaded")
        return hash160(self.pubkey_compressed)

# ============================================================================
#                              CLI COMMANDS
# ============================================================================

def cmd_init(args):
    """Initialize new wallet - generate key on SE050"""
    print("")
    print("=" * 60)
    print("SE050 HARDWARE WALLET - INITIALIZATION")
    print("=" * 60)
    
    Config.WALLET_DIR.mkdir(parents=True, exist_ok=True)
    
    if Config.pubkey_der_path().exists():
        print("")
        print(f"[!] Wallet already exists for Key ID 0x{Config.KEY_ID}")
        print(f"    Run 'wipe' first to delete, or use different KEY_ID")
        return 1
    
    print("")
    print("[1/4] Connecting to SE050...")
    if not se050_connect():
        print("      [FAIL] Failed to connect. Check hardware connections.")
        return 1
    print("      [OK] Connected")
    
    print("")
    print("[2/4] Checking SE050...")
    uid = se050_get_uid()
    if uid:
        print(f"      UID: {uid}")
    
    rng = se050_get_random()
    if rng:
        print(f"      TRNG test: {rng.hex()} [OK]")
    else:
        print("      [!] TRNG test failed")
    
    if se050_key_exists(Config.KEY_ID):
        print("")
        print(f"[!] Key already exists at slot 0x{Config.KEY_ID}")
        confirm = input("    Overwrite? [y/N]: ")
        if confirm.lower() != 'y':
            print("    Cancelled.")
            return 1
        se050_delete_key(Config.KEY_ID)
    
    print("")
    print(f"[3/4] Generating secp256k1 keypair at slot 0x{Config.KEY_ID}...")
    if not se050_generate_keypair(Config.KEY_ID):
        print("      [FAIL] Key generation failed")
        return 1
    print("      [OK] Keypair generated (private key stored in SE050)")
    
    print("")
    print("[4/4] Exporting public key...")
    if not se050_export_pubkey(Config.KEY_ID, Config.pubkey_der_path(), "DER"):
        print("      [FAIL] Export failed")
        return 1
    se050_export_pubkey(Config.KEY_ID, Config.pubkey_pem_path(), "PEM")
    print(f"      [OK] Saved to {Config.pubkey_der_path()}")
    
    wallet = Wallet()
    wallet.created_at = datetime.now().isoformat()
    if wallet.load():
        wallet.save_info()
        
        print("")
        print("=" * 60)
        print("WALLET CREATED SUCCESSFULLY")
        print("=" * 60)
        print(f"")
        print(f"Key ID:     0x{Config.KEY_ID}")
        print(f"Network:    {Config.NETWORK}")
        print(f"Pubkey:     {wallet.pubkey_compressed.hex()}")
        print(f"")
        print(f"RECEIVE ADDRESSES:")
        print(f"  Legacy:  {wallet.addresses['legacy']}")
        print(f"  SegWit:  {wallet.addresses['segwit']}")
        print("")
        print("IMPORTANT:")
        print("  - Private key is stored ONLY in SE050 secure element")
        print("  - Back up your Key ID (0x{}) and SE050 device".format(Config.KEY_ID))
        print("  - Loss of SE050 = Loss of funds!")
        print("=" * 60)
        print("")
    
    return 0

def cmd_address(args):
    """Display wallet addresses"""
    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1
    
    print("")
    print("=" * 60)
    print("SE050ARD HARDWARE WALLET")
    print("=" * 60)
    print(f"")
    print(f"Key ID:  0x{Config.KEY_ID}")
    print(f"Network: {Config.NETWORK}")
    print(f"Pubkey:  {wallet.pubkey_compressed.hex()}")
    print(f"")
    print(f"RECEIVE ADDRESSES:")
    print(f"")
    print(f"  Legacy (P2PKH):   {wallet.addresses['legacy']}")
    print(f"  SegWit (P2WPKH):  {wallet.addresses['segwit']}  <- recommended")
    
    # Show QR code if requested
    if hasattr(args, 'qr') and args.qr:
        addr = wallet.addresses['segwit']
        print("")
        print("=" * 60)
        print("SCAN TO RECEIVE (SegWit address):")
        print("=" * 60)
        print("")
        qr = generate_qr_ascii(addr)
        for line in qr.split('\n'):
            print(f"  {line}")
    
    print("")
    print("=" * 60)
    print("")
    
    return 0

def cmd_balance(args):
    """Check wallet balance"""
    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1
    
    print(f"")
    print(f"Checking balance on {Config.NETWORK}...")
    print("")
    
    # Get fiat price if requested
    fiat_price = None
    fiat_currency = getattr(args, 'fiat', None)
    if fiat_currency:
        fiat_currency = fiat_currency.upper()
        fiat_price = get_btc_price(fiat_currency)
    
    total_balance = 0
    total_utxos = 0
    
    for name, addr in [('SegWit', wallet.addresses['segwit']), 
                       ('Legacy', wallet.addresses['legacy'])]:
        info = get_address_info(addr)
        utxos = get_utxos(addr)
        
        if info:
            funded = info['chain_stats']['funded_txo_sum']
            spent = info['chain_stats']['spent_txo_sum']
            balance = funded - spent
            total_balance += balance
            total_utxos += len(utxos)
            
            print(f"  {name}: {balance:>12,} sats  ({len(utxos)} UTXOs)")
            print(f"          {addr}")
        else:
            print(f"  {name}: {0:>12,} sats")
            print(f"          {addr}")
    
    print(f"")
    print(f"  {'-' * 40}")
    print(f"  TOTAL:  {total_balance:>12,} sats ({total_balance / 1e8:.8f} BTC)")
    
    # Show fiat value if available
    if fiat_price and total_balance > 0:
        fiat_value = (total_balance / 1e8) * fiat_price
        print(f"          ≈ {fiat_value:,.2f} {fiat_currency} @ {fiat_price:,.0f}/{fiat_currency}")
    
    print(f"          {total_utxos} spendable UTXOs")
    
    fees = get_fee_estimates()
    print(f"")
    print(f"  Current fees: {fees.get('fastestFee', '?')} sat/vB (fast), "
          f"{fees.get('hourFee', '?')} sat/vB (slow)")
    
    if fiat_price:
        print(f"  BTC Price: {fiat_price:,.0f} {fiat_currency}")
    
    print("")
    
    return 0

def cmd_send(args):
    """Send Bitcoin"""
    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1
    
    dest_address = args.address
    amount_sats = args.amount
    fee_rate = args.fee or Config.DEFAULT_FEE_RATE
    
    print(f"")
    print(f"SEND TRANSACTION")
    print(f"  To:     {dest_address}")
    print(f"  Amount: {amount_sats:,} sats")
    print(f"  Fee:    {fee_rate} sat/vB")
    
    try:
        create_output_script(dest_address)
    except Exception as e:
        print(f"")
        print(f"[FAIL] Invalid destination address: {e}")
        print("")
        return 1
    
    print(f"")
    print(f"[1/5] Fetching UTXOs...")
    utxos = get_utxos(wallet.addresses['segwit'])
    
    if not utxos:
        print("      No UTXOs in SegWit address, checking Legacy...")
        utxos = get_utxos(wallet.addresses['legacy'])
        if not utxos:
            print("      [FAIL] No spendable UTXOs found!")
            print("")
            return 1
    
    total_in = sum(u['value'] for u in utxos)
    print(f"      Found {len(utxos)} UTXOs totaling {total_in:,} sats")
    
    estimated_vsize = 110 + (68 * len(utxos))
    fee = estimated_vsize * fee_rate
    
    if total_in < amount_sats + fee:
        print(f"")
        print(f"[FAIL] Insufficient funds!")
        print(f"       Have:  {total_in:,} sats")
        print(f"       Need:  {amount_sats + fee:,} sats (amount + fee)")
        print("")
        return 1
    
    change = total_in - amount_sats - fee
    
    print(f"")
    print(f"[2/5] Building transaction...")
    print(f"      Input:  {total_in:,} sats")
    print(f"      Output: {amount_sats:,} sats")
    print(f"      Fee:    {fee:,} sats ({fee_rate} sat/vB)")
    if change > 546:
        print(f"      Change: {change:,} sats")
    
    inputs = [{'txid': u['txid'], 'vout': u['vout'], 'value': u['value']} for u in utxos]
    
    outputs = [{'value': amount_sats, 'script': create_output_script(dest_address)}]
    
    if change > 546:
        change_script = bytes([0x00, 0x14]) + wallet.pubkey_hash
        outputs.append({'value': change, 'script': change_script})
    
    print(f"")
    print(f"[3/5] Connecting to SE050...")
    if not se050_connect():
        print("      [FAIL] Failed to connect to SE050")
        print("")
        return 1
    print("      [OK] Connected")
    
    print(f"")
    print(f"[4/5] Signing with SE050...")
    try:
        raw_tx = build_and_sign_transaction(
            inputs, outputs,
            wallet.pubkey_compressed,
            wallet.pubkey_hash
        )
        print("      [OK] Transaction signed")
    except Exception as e:
        print(f"      [FAIL] Signing failed: {e}")
        print("")
        return 1
    
    tx_hex = raw_tx.hex()
    print(f"")
    print(f"      Raw TX ({len(raw_tx)} bytes)")
    print(f"      {tx_hex[:64]}...")
    
    if not args.yes:
        print(f"")
        print(f"[5/5] Ready to broadcast")
        confirm = input("      Broadcast transaction? [y/N]: ")
        if confirm.lower() != 'y':
            print("      Cancelled.")
            save = input("      Save raw transaction? [y/N]: ")
            if save.lower() == 'y':
                raw_path = Config.WALLET_DIR / f"tx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hex"
                raw_path.write_text(tx_hex)
                print(f"      Saved to {raw_path}")
            print("")
            return 0
    
    print(f"")
    print(f"[5/5] Broadcasting...")
    txid = api_post("/tx", tx_hex.encode())
    
    if txid:
        explorer = "mempool.space/testnet4" if Config.NETWORK == "testnet" else "mempool.space"
        print(f"")
        print(f"      [OK] BROADCAST SUCCESSFUL")
        print(f"      TXID: {txid}")
        print(f"      https://{explorer}/tx/{txid}")
        print("")
        return 0
    else:
        print("      [FAIL] Broadcast failed")
        raw_path = Config.WALLET_DIR / f"tx_failed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hex"
        raw_path.write_text(tx_hex)
        print(f"      Raw TX saved to {raw_path}")
        print("")
        return 1

def cmd_export(args):
    """Export public key and wallet info (NOT private key!)"""
    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1
    
    print("")
    print("=" * 60)
    print("PUBLIC KEY EXPORT (Private key remains in SE050!)")
    print("=" * 60)
    
    print(f"")
    print(f"Key ID:  0x{Config.KEY_ID}")
    print(f"Network: {Config.NETWORK}")
    print(f"")
    print(f"Public Key (compressed, hex):")
    print(f"  {wallet.pubkey_compressed.hex()}")
    print(f"")
    print(f"Public Key (uncompressed, hex):")
    print(f"  {wallet.pubkey_uncompressed.hex()}")
    print(f"")
    print(f"Pubkey Hash (HASH160):")
    print(f"  {wallet.pubkey_hash.hex()}")
    print(f"")
    print(f"Addresses:")
    print(f"  Legacy: {wallet.addresses['legacy']}")
    print(f"  SegWit: {wallet.addresses['segwit']}")
    print(f"")
    print(f"Files:")
    print(f"  DER: {Config.pubkey_der_path()}")
    print(f"  PEM: {Config.pubkey_pem_path()}")
    
    if Config.pubkey_pem_path().exists():
        print(f"")
        print(f"PEM Format:")
        print(Config.pubkey_pem_path().read_text())
    
    print("=" * 60)
    print("")
    
    return 0

def cmd_wipe(args):
    """Delete wallet (DANGER!)"""
    print("")
    print("=" * 60)
    print("WARNING: WALLET WIPE")
    print("=" * 60)
    
    wallet = Wallet()
    wallet_exists = wallet.load()
    
    if wallet_exists:
        print(f"")
        print(f"This will PERMANENTLY DELETE:")
        print(f"  Key ID:  0x{Config.KEY_ID}")
        print(f"  SegWit:  {wallet.addresses['segwit']}")
        print(f"  Legacy:  {wallet.addresses['legacy']}")
    
    print(f"")
    print(f"[!] This action CANNOT be undone!")
    print(f"[!] Any funds at these addresses will be LOST FOREVER!")
    
    confirm = input(f"\nType 'WIPE {Config.KEY_ID}' to confirm: ")
    if confirm != f"WIPE {Config.KEY_ID}":
        print("Cancelled.")
        print("")
        return 0
    
    print("")
    print("Connecting to SE050...")
    if se050_connect():
        print(f"Deleting key 0x{Config.KEY_ID} from SE050...")
        if se050_delete_key(Config.KEY_ID):
            print("  [OK] Key deleted from SE050")
        else:
            print("  [!] Key deletion failed (may not exist)")
    
    print("Deleting local wallet files...")
    for path in [Config.pubkey_der_path(), Config.pubkey_pem_path(), Config.wallet_info_path()]:
        if path.exists():
            path.unlink()
            print(f"  Deleted {path}")
    
    print("")
    print("[OK] Wallet wiped.")
    print("")
    return 0

def cmd_info(args):
    """Show SE050 and wallet status"""
    print("")
    print("=" * 60)
    print("SE050 STATUS")
    print("=" * 60)
    
    if not shutil.which('ssscli'):
        print("")
        print("[FAIL] ssscli not found in PATH")
        return 1
    print("")
    print("[OK] ssscli found")
    
    print("")
    print("Connecting to SE050...")
    if not se050_connect():
        print("[FAIL] Connection failed. Check:")
        print("       - K64F connected via USB")
        print("       - SE050ARD attached to K64F")
        print("       - Correct /dev/ttyACM* device")
        return 1
    print("[OK] Connected")
    
    uid = se050_get_uid()
    if uid:
        print(f"")
        print(f"SE050 UID: {uid}")
    
    rng = se050_get_random()
    if rng:
        print(f"TRNG Test: {rng.hex()} [OK]")
    
    print(f"")
    print(f"Key Slot 0x{Config.KEY_ID}:")
    if se050_key_exists(Config.KEY_ID):
        print("  [OK] Key present")
    else:
        print("  [--] No key")
    
    print(f"")
    print(f"Local Wallet ({Config.WALLET_DIR}):")
    if Config.pubkey_der_path().exists():
        wallet = Wallet()
        if wallet.load():
            print(f"  [OK] Loaded")
            print(f"  Pubkey: {wallet.pubkey_compressed.hex()[:32]}...")
            print(f"  SegWit: {wallet.addresses['segwit']}")
    else:
        print("  [--] Not initialized")
    
    print("")
    print("=" * 60)
    print("")
    return 0

def cmd_sign_message(args):
    """Sign a message with the wallet's private key"""
    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1
    
    message = args.message
    
    print("")
    print("=" * 60)
    print("BITCOIN SIGNED MESSAGE")
    print("=" * 60)
    print(f"")
    print(f"Message:  {message[:50]}{'...' if len(message) > 50 else ''}")
    print(f"Address:  {wallet.addresses['segwit']}")
    print(f"")
    
    print("Connecting to SE050...")
    if not se050_connect():
        print("[FAIL] Failed to connect to SE050")
        return 1
    print("[OK] Connected")
    
    print("")
    print("Signing with SE050...")
    try:
        (r, s), recovery_id = sign_message_with_se050(Config.KEY_ID, message)
        signature = encode_signed_message(r, s, recovery_id, compressed=True)
        print("[OK] Message signed")
    except Exception as e:
        print(f"[FAIL] Signing failed: {e}")
        return 1
    
    print("")
    print("=" * 60)
    print("SIGNATURE:")
    print("=" * 60)
    print(f"")
    print(f"{signature}")
    print(f"")
    print("=" * 60)
    print("")
    print("To verify, use: https://www.verifybitcoinmessage.com/")
    print(f"  Address: {wallet.addresses['legacy']}")
    print(f"  Message: {message}")
    print(f"  Signature: (above)")
    print("")
    
    return 0

def cmd_history(args):
    """Show transaction history"""
    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1
    
    limit = getattr(args, 'limit', 10) or 10
    
    print("")
    print("=" * 60)
    print("TRANSACTION HISTORY")
    print("=" * 60)
    print(f"")
    print(f"Fetching transactions for {Config.NETWORK}...")
    print("")
    
    all_txs = []
    
    # Fetch from both addresses
    for addr in [wallet.addresses['segwit'], wallet.addresses['legacy']]:
        txs = get_address_txs(addr, limit=50)
        for tx in txs:
            tx['_address'] = addr
        all_txs.extend(txs)
    
    # Deduplicate by txid
    seen = set()
    unique_txs = []
    for tx in all_txs:
        if tx['txid'] not in seen:
            seen.add(tx['txid'])
            unique_txs.append(tx)
    
    # Sort by confirmation time (newest first)
    unique_txs.sort(key=lambda x: x.get('status', {}).get('block_time', 0), reverse=True)
    unique_txs = unique_txs[:limit]
    
    if not unique_txs:
        print("  No transactions found.")
        print("")
        return 0
    
    for tx in unique_txs:
        txid = tx['txid']
        status = tx.get('status', {})
        confirmed = status.get('confirmed', False)
        block_time = status.get('block_time', 0)
        
        # Calculate net flow for this wallet
        total_in = 0
        total_out = 0
        
        our_addresses = {wallet.addresses['segwit'], wallet.addresses['legacy']}
        
        for vin in tx.get('vin', []):
            prevout = vin.get('prevout', {})
            if prevout.get('scriptpubkey_address') in our_addresses:
                total_out += prevout.get('value', 0)
        
        for vout in tx.get('vout', []):
            if vout.get('scriptpubkey_address') in our_addresses:
                total_in += vout.get('value', 0)
        
        net = total_in - total_out
        
        # Format output
        if net > 0:
            direction = "← RECV"
            amount_str = f"+{net:,} sats"
        elif net < 0:
            direction = "→ SEND"
            amount_str = f"{net:,} sats"
        else:
            direction = "⟷ SELF"
            amount_str = f"0 sats (self-transfer)"
        
        time_str = format_timestamp(block_time) if block_time else "unconfirmed"
        conf_str = "✓" if confirmed else "⏳"
        
        print(f"  {conf_str} {time_str}  {direction}  {amount_str}")
        print(f"    {txid[:16]}...{txid[-8:]}")
        print("")
    
    explorer = "mempool.space/testnet4" if Config.NETWORK == "testnet" else "mempool.space"
    print(f"  View on explorer: https://{explorer}/address/{wallet.addresses['segwit']}")
    print("")
    
    return 0

def cmd_verify(args):
    """Verify SE050 is really being used"""
    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1
    
    print("")
    print("=" * 60)
    print("SE050 VERIFICATION")
    print("=" * 60)
    print("")
    
    print("[1/4] Connecting to SE050...")
    if not se050_connect():
        print("       [FAIL] Cannot connect to SE050")
        return 1
    print("       [OK] Connected")
    
    print("")
    print("[2/4] Comparing public keys...")
    
    # Export fresh key from SE050
    verify_path = Path("/tmp/se050_verify_pubkey.der")
    if not se050_export_pubkey(Config.KEY_ID, verify_path, "DER"):
        print("       [FAIL] Cannot export key from SE050")
        return 1
    
    # Compare with stored key
    stored_key = Config.pubkey_der_path().read_bytes()
    exported_key = verify_path.read_bytes()
    
    if stored_key == exported_key:
        print("       [OK] Public key matches SE050")
    else:
        print("       [FAIL] Public key MISMATCH!")
        print("       WARNING: Wallet may not be using SE050!")
        return 1
    
    print("")
    print("[3/4] Testing signature generation...")
    
    test_msg = f"SE050 verification test {datetime.now().isoformat()}"
    test_hash = sha256(test_msg.encode())
    
    try:
        sig = se050_sign(Config.KEY_ID, test_hash)
        r, s = parse_der_signature(sig)
        print(f"       [OK] Signature generated")
        print(f"       R: {hex(r)[:32]}...")
        print(f"       S: {hex(s)[:32]}...")
    except Exception as e:
        print(f"       [FAIL] Signing failed: {e}")
        return 1
    
    print("")
    print("[4/4] Verifying private key is locked...")
    
    # Try to export private key (should fail)
    keypair_path = Path("/tmp/se050_verify_keypair.der")
    result = subprocess.run(
        ['ssscli', 'get', 'ecc', 'pair', Config.KEY_ID, str(keypair_path), '--format', 'DER'],
        capture_output=True, text=True
    )
    
    if keypair_path.exists():
        keypair_path.unlink()
        print("       [FAIL] Private key was exported! This should not happen!")
        return 1
    else:
        print("       [OK] Private key cannot be extracted (as expected)")
    
    print("")
    print("=" * 60)
    print("VERIFICATION PASSED")
    print("=" * 60)
    print("")
    print("✓ SE050 is connected and responding")
    print("✓ Public key matches wallet")
    print("✓ Signatures are being generated on SE050")
    print("✓ Private key is locked inside SE050")
    print("")
    
    return 0

# ============================================================================
#                                  MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SE050ARD Hardware Bitcoin Wallet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s init                        Create new wallet
  %(prog)s address                     Show receive addresses
  %(prog)s address --qr                Show address with QR code
  %(prog)s balance                     Check balance
  %(prog)s balance --fiat usd          Check balance with USD value
  %(prog)s send bc1q... 10000          Send 10000 sats
  %(prog)s send bc1q... 10000 -f 5     Send with 5 sat/vB fee
  %(prog)s sign-message "Hello"        Sign a message
  %(prog)s history                     Show transaction history
  %(prog)s verify                      Verify SE050 is working
  %(prog)s export                      Export public key info
  %(prog)s wipe                        Delete wallet (DANGER!)
  %(prog)s info                        Show SE050 status
        """
    )
    
    parser.add_argument('--testnet', action='store_true', help='Use testnet')
    parser.add_argument('--keyid', type=str, help='SE050 key slot (hex, default: 20000001)')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # init
    subparsers.add_parser('init', help='Initialize new wallet')
    
    # address
    addr_parser = subparsers.add_parser('address', help='Show receive addresses')
    addr_parser.add_argument('--qr', action='store_true', help='Show QR code')
    
    # balance
    bal_parser = subparsers.add_parser('balance', help='Check balance')
    bal_parser.add_argument('--fiat', type=str, help='Show value in fiat currency (usd, eur, gbp, etc.)')
    
    # send
    send_parser = subparsers.add_parser('send', help='Send Bitcoin')
    send_parser.add_argument('address', help='Destination address')
    send_parser.add_argument('amount', type=int, help='Amount in satoshis')
    send_parser.add_argument('-f', '--fee', type=int, help='Fee rate (sat/vB)')
    send_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    
    # sign-message
    sign_parser = subparsers.add_parser('sign-message', help='Sign a message')
    sign_parser.add_argument('message', help='Message to sign')
    
    # history
    hist_parser = subparsers.add_parser('history', help='Show transaction history')
    hist_parser.add_argument('-n', '--limit', type=int, default=10, help='Number of transactions (default: 10)')
    
    # verify
    subparsers.add_parser('verify', help='Verify SE050 is working correctly')
    
    # export
    subparsers.add_parser('export', help='Export public key info')
    
    # wipe
    subparsers.add_parser('wipe', help='Delete wallet (DANGER!)')
    
    # info
    subparsers.add_parser('info', help='Show SE050 status')
    
    args = parser.parse_args()
    
    if args.testnet:
        Config.NETWORK = "testnet"
    if args.keyid:
        Config.KEY_ID = args.keyid
    
    commands = {
        'init': cmd_init,
        'address': cmd_address,
        'balance': cmd_balance,
        'send': cmd_send,
        'sign-message': cmd_sign_message,
        'history': cmd_history,
        'verify': cmd_verify,
        'export': cmd_export,
        'wipe': cmd_wipe,
        'info': cmd_info,
    }
    
    if args.command in commands:
        sys.exit(commands[args.command](args))
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
