"""
SE050 Interface Module
======================

Provides unified interface to SE050 secure element.
Uses native C library (libse050_wallet.so) when available,
falls back to ssscli subprocess calls.

Copyright 2025 _SiCk @ afflicted.sh
SPDX-License-Identifier: MIT
"""

import subprocess
from pathlib import Path
from typing import Optional, List, Tuple
import time

# Try to load native C library
_USE_NATIVE = False
_native_lib = None

try:
    from . import se050_native as _native_lib
    _USE_NATIVE = True
except ImportError:
    try:
        # Try direct import if not in package
        import se050_native as _native_lib
        _USE_NATIVE = True
    except ImportError:
        pass

if not _USE_NATIVE:
    # Try ctypes approach
    try:
        import ctypes
        from ctypes import c_int, c_bool, c_uint8, c_uint32, c_size_t, c_char_p, POINTER, byref
        import os
        
        # Search for library in multiple locations
        _script_dir = Path(__file__).parent.resolve()
        _lib_paths = [
            # Relative to this script (most common for installed wallet)
            _script_dir / "lib" / "libse050_wallet.so",
            _script_dir / "lib" / "build" / "libse050_wallet.so",
            # Parent directory (if se050_interface.py is in a subdirectory)
            _script_dir.parent / "lib" / "libse050_wallet.so",
            _script_dir.parent / "lib" / "build" / "libse050_wallet.so",
            # Common installation paths
            Path.home() / "puzzle" / "se050ard_wallet" / "lib" / "libse050_wallet.so",
            Path.home() / "puzzle" / "se050ard_wallet" / "lib" / "build" / "libse050_wallet.so",
            Path.home() / "se050ard_wallet" / "lib" / "libse050_wallet.so",
            Path.home() / "se050ard_wallet" / "lib" / "build" / "libse050_wallet.so",
            # System paths
            Path("/usr/local/lib/libse050_wallet.so"),
            Path("/usr/lib/libse050_wallet.so"),
        ]
        
        # Also check LD_LIBRARY_PATH
        ld_path = os.environ.get("LD_LIBRARY_PATH", "")
        for p in ld_path.split(":"):
            if p:
                _lib_paths.append(Path(p) / "libse050_wallet.so")
        
        for path in _lib_paths:
            if path.exists():
                _native_lib = ctypes.CDLL(str(path))
                _USE_NATIVE = True
                
                # Set up function signatures
                _native_lib.se050_open_session.argtypes = [c_char_p, c_char_p]
                _native_lib.se050_open_session.restype = c_int
                _native_lib.se050_close_session.argtypes = []
                _native_lib.se050_close_session.restype = c_int
                _native_lib.se050_is_connected.argtypes = []
                _native_lib.se050_is_connected.restype = c_bool
                _native_lib.se050_get_uid.argtypes = [POINTER(c_uint8), POINTER(c_size_t)]
                _native_lib.se050_get_uid.restype = c_int
                _native_lib.se050_get_random.argtypes = [POINTER(c_uint8), c_size_t]
                _native_lib.se050_get_random.restype = c_int
                _native_lib.se050_key_exists.argtypes = [c_uint32]
                _native_lib.se050_key_exists.restype = c_bool
                _native_lib.se050_generate_keypair.argtypes = [c_uint32]
                _native_lib.se050_generate_keypair.restype = c_int
                _native_lib.se050_import_keypair.argtypes = [c_uint32, POINTER(c_uint8)]
                _native_lib.se050_import_keypair.restype = c_int
                _native_lib.se050_get_pubkey.argtypes = [c_uint32, POINTER(c_uint8), POINTER(c_size_t)]
                _native_lib.se050_get_pubkey.restype = c_int
                _native_lib.se050_delete_key.argtypes = [c_uint32]
                _native_lib.se050_delete_key.restype = c_int
                _native_lib.se050_sign_hash.argtypes = [c_uint32, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_size_t)]
                _native_lib.se050_sign_hash.restype = c_int
                _native_lib.se050_set_debug.argtypes = [c_bool]
                _native_lib.se050_set_debug.restype = None
                
                break
    except Exception:
        pass


class SE050Error(Exception):
    """SE050 operation failed"""
    pass


class SE050Config:
    """SE050 configuration"""
    CONNECTION_TYPE = "vcom"
    CONNECTION_PORT = None  # Auto-detect
    SCP_KEY_FILE = str(Path.home() / ".se050-wallet" / "scp03.key")
    
    @classmethod
    def get_connection_port(cls) -> str:
        if cls.CONNECTION_PORT:
            return cls.CONNECTION_PORT
        import glob
        devices = glob.glob('/dev/ttyACM*')
        if devices:
            return devices[0]
        devices = glob.glob('/dev/ttyUSB*')
        if devices:
            return devices[0]
        return "none"


def is_native_available() -> bool:
    """Check if native C library is available"""
    return _USE_NATIVE and _native_lib is not None


def get_backend() -> str:
    """Get current backend name"""
    return "native" if is_native_available() else "ssscli"


# ============================================================================
# Native Library Implementation
# ============================================================================

def _native_connect(port: str = None, scp_key_file: str = None, debug: bool = False) -> bool:
    """Connect using native C library"""
    if not _native_lib:
        raise SE050Error("Native library not loaded")
    
    if debug:
        _native_lib.se050_set_debug(True)
    
    port_bytes = (port or SE050Config.get_connection_port()).encode()
    key_bytes = (scp_key_file or SE050Config.SCP_KEY_FILE).encode()
    
    ret = _native_lib.se050_open_session(port_bytes, key_bytes)
    if ret != 0:
        raise SE050Error(f"Native session open failed: {ret}")
    return True


def _native_disconnect():
    """Disconnect using native C library"""
    if _native_lib:
        _native_lib.se050_close_session()


def _native_is_connected() -> bool:
    """Check connection using native C library"""
    if not _native_lib:
        return False
    return _native_lib.se050_is_connected()


def _native_get_uid() -> Optional[str]:
    """Get UID using native C library"""
    if not _native_lib:
        return None
    
    uid = (ctypes.c_uint8 * 18)()
    uid_len = ctypes.c_size_t(18)
    
    ret = _native_lib.se050_get_uid(uid, ctypes.byref(uid_len))
    if ret != 0:
        return None
    
    return bytes(uid[:uid_len.value]).hex()


def _native_get_random(num_bytes: int) -> Optional[bytes]:
    """Get random bytes using native C library"""
    if not _native_lib:
        return None
    
    buf = (ctypes.c_uint8 * num_bytes)()
    ret = _native_lib.se050_get_random(buf, num_bytes)
    if ret != 0:
        return None
    
    return bytes(buf)


def _native_key_exists(key_id: str) -> bool:
    """Check if key exists using native C library"""
    if not _native_lib:
        return False
    
    key_id_int = int(key_id, 16) if isinstance(key_id, str) else key_id
    return _native_lib.se050_key_exists(key_id_int)


def _native_generate_keypair(key_id: str, curve: str = "Secp256k1") -> bool:
    """Generate keypair using native C library"""
    if not _native_lib:
        raise SE050Error("Native library not loaded")
    
    key_id_int = int(key_id, 16) if isinstance(key_id, str) else key_id
    ret = _native_lib.se050_generate_keypair(key_id_int)
    if ret != 0:
        raise SE050Error(f"Key generation failed: {ret}")
    return True


def _native_set_keypair(key_id: str, private_key: bytes) -> bool:
    """Import keypair using native C library"""
    if not _native_lib:
        raise SE050Error("Native library not loaded")
    
    if len(private_key) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(private_key)}")
    
    key_id_int = int(key_id, 16) if isinstance(key_id, str) else key_id
    key_buf = (ctypes.c_uint8 * 32)(*private_key)
    
    ret = _native_lib.se050_import_keypair(key_id_int, key_buf)
    if ret != 0:
        raise SE050Error(f"Key import failed: {ret}")
    return True


def _native_export_pubkey(key_id: str, output_path: Path = None) -> bytes:
    """Export public key using native C library"""
    if not _native_lib:
        raise SE050Error("Native library not loaded")
    
    key_id_int = int(key_id, 16) if isinstance(key_id, str) else key_id
    pubkey = (ctypes.c_uint8 * 65)()
    pubkey_len = ctypes.c_size_t(65)
    
    ret = _native_lib.se050_get_pubkey(key_id_int, pubkey, ctypes.byref(pubkey_len))
    if ret != 0:
        raise SE050Error(f"Get pubkey failed: {ret}")
    
    pubkey_bytes = bytes(pubkey[:pubkey_len.value])
    
    if output_path:
        # Write raw pubkey (65 bytes uncompressed format starting with 0x04)
        output_path.write_bytes(pubkey_bytes)
    
    return pubkey_bytes


def _native_delete_key(key_id: str) -> bool:
    """Delete key using native C library"""
    if not _native_lib:
        raise SE050Error("Native library not loaded")
    
    key_id_int = int(key_id, 16) if isinstance(key_id, str) else key_id
    ret = _native_lib.se050_delete_key(key_id_int)
    if ret != 0:
        raise SE050Error(f"Key delete failed: {ret}")
    return True


def _native_sign(key_id: str, data: bytes) -> bytes:
    """Sign data using native C library"""
    if not _native_lib:
        raise SE050Error("Native library not loaded")
    
    key_id_int = int(key_id, 16) if isinstance(key_id, str) else key_id
    
    # Ensure data is 32 bytes (SHA256 hash)
    if len(data) != 32:
        import hashlib
        data = hashlib.sha256(data).digest()
    
    hash_buf = (ctypes.c_uint8 * 32)(*data)
    sig_buf = (ctypes.c_uint8 * 72)()
    sig_len = ctypes.c_size_t(72)
    
    ret = _native_lib.se050_sign_hash(key_id_int, hash_buf, sig_buf, ctypes.byref(sig_len))
    if ret != 0:
        raise SE050Error(f"Signing failed: {ret}")
    
    return bytes(sig_buf[:sig_len.value])


# ============================================================================
# ssscli Fallback Implementation
# ============================================================================

def _run_ssscli(args: List[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run ssscli command"""
    cmd = ['ssscli'] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SE050Error(f"ssscli failed: {result.stderr or result.stdout}")
    return result


def _ssscli_connect(retries: int = 3, debug: bool = False) -> bool:
    """Connect using ssscli"""
    port = SE050Config.get_connection_port()
    conn_type = SE050Config.CONNECTION_TYPE
    scp_key = SE050Config.SCP_KEY_FILE
    
    for attempt in range(retries):
        try:
            # Check if already connected
            verify = subprocess.run(
                ['ssscli', 'se05x', 'uid'],
                capture_output=True, text=True, timeout=10
            )
            combined = (verify.stdout + verify.stderr).lower()
            if verify.returncode == 0 and 'uid' in combined:
                return True
            
            # Connect with SCP03
            result = subprocess.run(
                ['ssscli', 'connect', 'se05x', conn_type, port,
                 '--auth_type', 'PlatformSCP', '--scpkey', scp_key],
                capture_output=True, text=True, timeout=15
            )
            
            time.sleep(0.5)
            
            # Verify
            verify = subprocess.run(
                ['ssscli', 'se05x', 'uid'],
                capture_output=True, text=True, timeout=10
            )
            combined = (verify.stdout + verify.stderr).lower()
            if verify.returncode == 0 and 'uid' in combined:
                return True
            
            if attempt < retries - 1:
                subprocess.run(['ssscli', 'disconnect'], capture_output=True, timeout=5)
                time.sleep(0.5)
                
        except Exception as e:
            if debug:
                print(f"Connection error: {e}")
            time.sleep(0.5)
    
    return False


def _ssscli_disconnect():
    """Disconnect using ssscli"""
    try:
        subprocess.run(['ssscli', 'disconnect'], capture_output=True, timeout=5)
    except:
        pass


def _ssscli_is_connected() -> bool:
    """Check connection using ssscli"""
    try:
        result = _run_ssscli(['se05x', 'uid'], check=False)
        return result.returncode == 0
    except:
        return False


def _ssscli_get_uid() -> Optional[str]:
    """Get UID using ssscli"""
    try:
        result = _run_ssscli(['se05x', 'uid'])
        for line in result.stdout.split('\n'):
            if 'uid' in line.lower() or len(line.strip()) == 36:
                uid = ''.join(c for c in line if c in '0123456789abcdefABCDEF')
                if len(uid) >= 16:
                    return uid
        return None
    except:
        return None


def _ssscli_get_random(num_bytes: int) -> Optional[bytes]:
    """Get random bytes using ssscli"""
    collected = bytearray()
    calls_needed = (num_bytes + 9) // 10
    
    for _ in range(calls_needed):
        try:
            result = _run_ssscli(['se05x', 'getrng'])
            for line in result.stdout.split('\n'):
                if 'random' in line.lower():
                    hex_str = ''.join(c for c in line if c in '0123456789abcdefABCDEF')
                    if hex_str:
                        collected.extend(bytes.fromhex(hex_str))
                        break
        except:
            break
    
    return bytes(collected[:num_bytes]) if len(collected) >= num_bytes else None


def _ssscli_key_exists(key_id: str) -> bool:
    """Check if key exists using ssscli"""
    try:
        temp_file = Path(f"/tmp/check_{key_id}.der")
        result = _run_ssscli(['get', 'ecc', 'pub', key_id, str(temp_file), '--format', 'DER'], check=False)
        if temp_file.exists():
            temp_file.unlink()
        return result.returncode == 0
    except:
        return False


def _ssscli_generate_keypair(key_id: str, curve: str = "Secp256k1") -> bool:
    """Generate keypair using ssscli"""
    try:
        _run_ssscli(['generate', 'ecc', key_id, curve])
        return True
    except SE050Error as e:
        print(f"Key generation failed: {e}")
        return False


def _ssscli_export_pubkey(key_id: str, output_path: Path, format: str = "DER") -> bool:
    """Export public key using ssscli"""
    try:
        _run_ssscli(['get', 'ecc', 'pub', key_id, str(output_path), '--format', format])
        return True
    except SE050Error as e:
        print(f"Public key export failed: {e}")
        return False


def _ssscli_delete_key(key_id: str) -> bool:
    """Delete key using ssscli"""
    try:
        _run_ssscli(['erase', key_id])
        return True
    except SE050Error as e:
        print(f"Key deletion failed: {e}")
        return False


def _ssscli_sign(key_id: str, data: bytes) -> bytes:
    """Sign data using ssscli"""
    data_file = Path("/tmp/se050_sign_input.bin")
    sig_file = Path("/tmp/se050_signature.der")
    
    try:
        data_file.write_bytes(data)
        
        _run_ssscli([
            'sign', key_id,
            str(data_file), str(sig_file),
            '--informat', 'DER',
            '--outformat', 'DER',
            '--hashalgo', 'SHA256'
        ])
        
        return sig_file.read_bytes()
        
    finally:
        if data_file.exists():
            data_file.unlink()
        if sig_file.exists():
            sig_file.unlink()


# ============================================================================
# Unified Public API
# ============================================================================

def connect(retries: int = 3, debug: bool = False) -> bool:
    """Connect to SE050 (auto-selects best backend)"""
    if is_native_available():
        try:
            return _native_connect(debug=debug)
        except Exception as e:
            if debug:
                print(f"Native connect failed: {e}, falling back to ssscli")
    return _ssscli_connect(retries=retries, debug=debug)


def disconnect():
    """Disconnect from SE050"""
    if is_native_available() and _native_is_connected():
        _native_disconnect()
    else:
        _ssscli_disconnect()


def reconnect(debug: bool = False) -> bool:
    """Reconnect to SE050"""
    disconnect()
    time.sleep(0.5)
    return connect(debug=debug)


def is_connected() -> bool:
    """Check if connected to SE050"""
    if is_native_available():
        return _native_is_connected()
    return _ssscli_is_connected()


def check_connection() -> bool:
    """Check if SE050 is accessible"""
    return is_connected() or connect()


def get_uid() -> Optional[str]:
    """Get SE050 unique identifier"""
    if is_native_available() and _native_is_connected():
        return _native_get_uid()
    return _ssscli_get_uid()


def get_random(num_bytes: int = 16) -> Optional[bytes]:
    """Get random bytes from SE050 TRNG"""
    if is_native_available() and _native_is_connected():
        return _native_get_random(num_bytes)
    return _ssscli_get_random(num_bytes)


def key_exists(key_id: str) -> bool:
    """Check if key exists in SE050"""
    if is_native_available() and _native_is_connected():
        return _native_key_exists(key_id)
    return _ssscli_key_exists(key_id)


def generate_keypair(key_id: str, curve: str = "Secp256k1") -> bool:
    """Generate ECC keypair on SE050"""
    if is_native_available() and _native_is_connected():
        return _native_generate_keypair(key_id, curve)
    return _ssscli_generate_keypair(key_id, curve)


def set_ecc_keypair(key_id: str, private_key: bytes, curve: str = "Secp256k1") -> bool:
    """Import ECC keypair to SE050"""
    if is_native_available() and _native_is_connected():
        return _native_set_keypair(key_id, private_key)
    # ssscli version is more complex, keep the original implementation
    raise SE050Error("set_ecc_keypair requires native library or original ssscli implementation")


def export_pubkey(key_id: str, output_path: Path = None, format: str = "DER") -> bytes:
    """Export public key from SE050. Returns pubkey bytes."""
    if is_native_available() and _native_is_connected():
        return _native_export_pubkey(key_id, output_path)
    if output_path:
        _ssscli_export_pubkey(key_id, output_path, format)
        return output_path.read_bytes()
    # Fallback: use temp file
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
        tmp_path = Path(f.name)
    _ssscli_export_pubkey(key_id, tmp_path, format)
    data = tmp_path.read_bytes()
    tmp_path.unlink()
    return data


def delete_key(key_id: str) -> bool:
    """Delete key from SE050"""
    if is_native_available() and _native_is_connected():
        return _native_delete_key(key_id)
    return _ssscli_delete_key(key_id)


def sign(key_id: str, data: bytes) -> bytes:
    """Sign data using SE050 key"""
    if is_native_available() and _native_is_connected():
        return _native_sign(key_id, data)
    return _ssscli_sign(key_id, data)


# ============================================================================
# Compatibility aliases
# ============================================================================

se050_connect = connect
se050_disconnect = disconnect
se050_reconnect = reconnect
se050_check_connection = check_connection
se050_get_uid = get_uid
se050_get_random = get_random
se050_key_exists = key_exists
se050_generate_keypair = generate_keypair
se050_set_ecc_keypair = set_ecc_keypair
se050_export_pubkey = export_pubkey
se050_delete_key = delete_key
se050_sign = sign


if __name__ == "__main__":
    print(f"SE050 Interface Module")
    print(f"Backend: {get_backend()}")
    print(f"Native available: {is_native_available()}")
    
    print("\nTesting connection...")
    if connect(debug=True):
        print(f"Connected: {is_connected()}")
        uid = get_uid()
        print(f"UID: {uid}")
        
        rng = get_random(16)
        print(f"Random: {rng.hex() if rng else 'Failed'}")
        
        disconnect()
        print("Disconnected")
    else:
        print("Connection failed")
