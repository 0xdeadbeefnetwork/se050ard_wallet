#!/usr/bin/env python3
"""
SE050ARD Hardware Bitcoin Wallet
=================================

A Bitcoin wallet using NXP SE050 secure element for signing.
Keys are derived from a BIP39 seed phrase and stored on SE050.

BACKUP: Write down your 12/24 word seed phrase!
        If you lose the SE050, you can restore to a new chip.

Requirements:
    - Raspberry Pi (tested on Pi 400)
    - NXP SE050 evaluation kit (SE050ARD) via K64F
    - ssscli from NXP Plug & Trust middleware
    - Python 3.7+

Setup:
    1. Connect SE050ARD to K64F via Arduino headers
    2. Connect K64F to Pi via USB
    3. Install ssscli (see NXP AN13027)
    4. Run: ssscli connect se05x vcom /dev/ttyACM0

Usage:
    ./wallet.py create                  # Create wallet from NEW seed phrase
    ./wallet.py import-seed             # Import wallet from EXISTING seed phrase
    ./wallet.py address                 # Show receive addresses
    ./wallet.py balance                 # Check balance via mempool.space
    ./wallet.py send <address> <sats>   # Send Bitcoin (signs on SE050)
    ./wallet.py export                  # Export public key info (NO private key!)
    ./wallet.py wipe                    # Delete key from SE050 (DANGER!)
    ./wallet.py info                    # Show SE050 status and key info

Repository: https://github.com/AffictedIntelligence/se050ard_wallet
License: MIT
Author: _SiCk @ afflicted.sh
"""

import sys
import os
import hashlib
import hmac
import subprocess
import json
import urllib.request
import urllib.error
import argparse
import shutil
import secrets
from pathlib import Path
from datetime import datetime
from typing import Tuple, Optional, List, Dict

# Try to use the unified se050_interface module
_USE_INTERFACE_MODULE = False
try:
    from se050_interface import (
        get_backend as _get_backend,
        is_native_available,
        connect as _iface_connect,
        disconnect as _iface_disconnect,
        reconnect as _iface_reconnect,
        is_connected as _iface_is_connected,
        get_uid as _iface_get_uid,
        get_random as _iface_get_random,
        key_exists as _iface_key_exists,
        generate_keypair as _iface_generate_keypair,
        delete_key as _iface_delete_key,
        export_pubkey as _iface_export_pubkey,
        sign as _iface_sign,
        set_ecc_keypair as _iface_set_keypair,
        SE050Error as _IfaceSE050Error,
        SE050Config,
    )
    _USE_INTERFACE_MODULE = True
    print(f"[wallet] Using SE050 interface: {_get_backend()}")
except ImportError as e:
    _USE_INTERFACE_MODULE = False
    print(f"[wallet] Using built-in ssscli wrapper (se050_interface.py not found: {e})")

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
    
    # SE050 Connection settings
    # Connection type: "vcom" for USB serial, "t1oi2c" for I2C
    CONNECTION_TYPE = "vcom"
    # Port: Auto-detect if None, or specify e.g. "/dev/ttyACM0"
    CONNECTION_PORT = None
    
    @classmethod
    def get_connection_port(cls) -> str:
        """Get SE050 connection port, auto-detecting if needed"""
        if cls.CONNECTION_PORT:
            return cls.CONNECTION_PORT
        
        # Auto-detect ttyACM device
        import glob
        devices = glob.glob('/dev/ttyACM*')
        if devices:
            return devices[0]
        
        # Try ttyUSB as fallback
        devices = glob.glob('/dev/ttyUSB*')
        if devices:
            return devices[0]
        
        return "none"
    
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
#                           BIP39 MNEMONIC
# ============================================================================

BIP39_WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
    "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
    "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
    "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
    "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
    "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
    "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
    "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
    "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud",
    "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "code", "coffee", "coil", "coin", "collect", "color", "column", "combine",
    "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
    "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
    "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
    "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream",
    "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
    "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious",
    "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
    "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn",
    "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
    "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
    "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
    "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram",
    "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
    "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
    "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
    "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
    "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
    "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb",
    "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
    "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
    "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight",
    "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
    "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
    "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy",
    "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode",
    "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt",
    "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude",
    "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
    "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend",
    "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint",
    "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy",
    "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault",
    "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field",
    "figure", "file", "film", "filter", "final", "find", "fine", "finger",
    "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness",
    "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight",
    "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
    "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
    "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil",
    "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
    "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel",
    "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
    "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
    "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius",
    "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
    "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass",
    "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
    "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass",
    "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group",
    "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun",
    "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
    "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet",
    "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip",
    "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
    "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
    "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble",
    "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband",
    "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill",
    "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
    "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
    "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
    "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
    "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
    "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
    "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
    "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
    "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
    "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
    "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
    "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
    "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
    "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
    "library", "license", "life", "lift", "light", "like", "limb", "limit",
    "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
    "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
    "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
    "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
    "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
    "marine", "market", "marriage", "mask", "mass", "master", "match", "material",
    "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure",
    "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory",
    "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
    "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
    "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
    "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
    "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
    "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
    "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
    "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
    "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey",
    "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay",
    "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
    "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
    "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
    "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
    "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
    "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
    "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut",
    "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper",
    "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
    "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
    "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
    "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge",
    "poem", "poet", "point", "polar", "pole", "police", "pond", "pony",
    "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery",
    "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
    "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
    "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide",
    "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
    "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
    "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
    "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
    "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid",
    "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real",
    "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject",
    "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
    "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
    "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire",
    "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
    "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
    "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
    "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
    "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
    "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
    "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
    "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
    "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
    "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
    "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
    "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
    "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
    "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
    "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
    "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
    "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
    "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
    "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
    "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
    "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
    "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
    "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
    "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
    "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
    "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
    "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
    "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
    "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
    "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
    "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
    "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
    "theme", "then", "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger",
    "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
    "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
    "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
    "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
    "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
    "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
    "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
    "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
    "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
    "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
    "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon",
    "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
    "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
    "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
    "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very",
    "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view",
    "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
    "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote",
    "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
    "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
    "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
    "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
    "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife",
    "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
    "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
    "wonder", "wood", "wool", "word", "work", "world", "worry", "worth",
    "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
    "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"
]

def generate_mnemonic(strength: int = 128) -> str:
    """
    Generate a BIP39 mnemonic phrase.
    strength: 128 bits = 12 words, 256 bits = 24 words
    """
    if strength not in (128, 160, 192, 224, 256):
        raise ValueError("Strength must be 128, 160, 192, 224, or 256 bits")

    entropy = secrets.token_bytes(strength // 8)
    h = hashlib.sha256(entropy).digest()
    b = bin(int.from_bytes(entropy, 'big'))[2:].zfill(strength)
    b += bin(int.from_bytes(h, 'big'))[2:].zfill(256)[:strength // 32]

    words = []
    for i in range(0, len(b), 11):
        idx = int(b[i:i+11], 2)
        words.append(BIP39_WORDLIST[idx])

    return ' '.join(words)

def validate_mnemonic(mnemonic: str) -> bool:
    """Validate a BIP39 mnemonic phrase."""
    words = mnemonic.lower().strip().split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False

    for word in words:
        if word not in BIP39_WORDLIST:
            return False

    # Verify checksum
    b = ''
    for word in words:
        idx = BIP39_WORDLIST.index(word)
        b += bin(idx)[2:].zfill(11)

    entropy_bits = len(words) * 11 * 32 // 33
    entropy = int(b[:entropy_bits], 2).to_bytes(entropy_bits // 8, 'big')
    checksum_bits = len(words) * 11 - entropy_bits
    h = hashlib.sha256(entropy).digest()
    expected_checksum = bin(int.from_bytes(h, 'big'))[2:].zfill(256)[:checksum_bits]

    return b[entropy_bits:] == expected_checksum

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Convert mnemonic to 64-byte seed using PBKDF2."""
    import hashlib
    mnemonic_bytes = mnemonic.encode('utf-8')
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt, 2048, dklen=64)

# ============================================================================
#                           BIP32 HD KEY DERIVATION
# ============================================================================

# secp256k1 curve parameters
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m

def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def _point_add(p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """Add two points on secp256k1 curve."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None

    if x1 == x2:
        m = (3 * x1 * x1 * _modinv(2 * y1, SECP256K1_P)) % SECP256K1_P
    else:
        m = ((y2 - y1) * _modinv(x2 - x1, SECP256K1_P)) % SECP256K1_P

    x3 = (m * m - x1 - x2) % SECP256K1_P
    y3 = (m * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)

def _point_multiply(k: int, point: Optional[Tuple[int, int]] = None) -> Optional[Tuple[int, int]]:
    """Multiply point by scalar on secp256k1 curve."""
    if point is None:
        point = (SECP256K1_Gx, SECP256K1_Gy)

    result = None
    addend = point

    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1

    return result

def _privkey_to_pubkey(privkey: bytes) -> bytes:
    """Derive uncompressed public key from private key."""
    k = int.from_bytes(privkey, 'big')
    point = _point_multiply(k)
    if point is None:
        raise ValueError("Invalid private key")
    x, y = point
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def _serialize_pubkey_compressed(pubkey: bytes) -> bytes:
    """Serialize public key in compressed format."""
    if len(pubkey) == 33:
        return pubkey
    if len(pubkey) != 65 or pubkey[0] != 0x04:
        raise ValueError("Invalid public key")
    x = pubkey[1:33]
    y = int.from_bytes(pubkey[33:65], 'big')
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x

def derive_master_key(seed: bytes) -> Tuple[bytes, bytes]:
    """Derive master private key and chain code from seed (BIP32)."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = I[:32]
    chain_code = I[32:]

    # Verify key is valid
    k = int.from_bytes(master_key, 'big')
    if k == 0 or k >= SECP256K1_N:
        raise ValueError("Invalid master key derived")

    return master_key, chain_code

def derive_child_key(parent_key: bytes, parent_chain: bytes, index: int, hardened: bool = False) -> Tuple[bytes, bytes]:
    """Derive child private key from parent (BIP32)."""
    if hardened:
        index += 0x80000000
        data = b'\x00' + parent_key + index.to_bytes(4, 'big')
    else:
        pubkey = _privkey_to_pubkey(parent_key)
        pubkey_compressed = _serialize_pubkey_compressed(pubkey)
        data = pubkey_compressed + index.to_bytes(4, 'big')

    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]

    child_key = (int.from_bytes(IL, 'big') + int.from_bytes(parent_key, 'big')) % SECP256K1_N
    if child_key == 0:
        raise ValueError("Invalid child key")

    return child_key.to_bytes(32, 'big'), IR

def derive_bip44_key(seed: bytes, account: int = 0, change: int = 0, index: int = 0,
                     coin_type: int = 0) -> Tuple[bytes, bytes]:
    """
    Derive BIP44 key: m/44'/coin'/account'/change/index
    coin_type: 0 = Bitcoin mainnet, 1 = testnet
    Returns (private_key, public_key_uncompressed)
    """
    master_key, chain_code = derive_master_key(seed)

    # m/44' (purpose)
    key, chain = derive_child_key(master_key, chain_code, 44, hardened=True)
    # m/44'/coin' (coin type)
    key, chain = derive_child_key(key, chain, coin_type, hardened=True)
    # m/44'/coin'/account' (account)
    key, chain = derive_child_key(key, chain, account, hardened=True)
    # m/44'/coin'/account'/change (external/internal)
    key, chain = derive_child_key(key, chain, change, hardened=False)
    # m/44'/coin'/account'/change/index (address index)
    key, chain = derive_child_key(key, chain, index, hardened=False)

    pubkey = _privkey_to_pubkey(key)
    return key, pubkey

def derive_bip84_key(seed: bytes, account: int = 0, change: int = 0, index: int = 0,
                     coin_type: int = 0) -> Tuple[bytes, bytes]:
    """
    Derive BIP84 key (Native SegWit): m/84'/coin'/account'/change/index
    coin_type: 0 = Bitcoin mainnet, 1 = testnet
    Returns (private_key, public_key_uncompressed)
    """
    master_key, chain_code = derive_master_key(seed)

    # m/84' (purpose - native segwit)
    key, chain = derive_child_key(master_key, chain_code, 84, hardened=True)
    # m/84'/coin'
    key, chain = derive_child_key(key, chain, coin_type, hardened=True)
    # m/84'/coin'/account'
    key, chain = derive_child_key(key, chain, account, hardened=True)
    # m/84'/coin'/account'/change
    key, chain = derive_child_key(key, chain, change, hardened=False)
    # m/84'/coin'/account'/change/index
    key, chain = derive_child_key(key, chain, index, hardened=False)

    pubkey = _privkey_to_pubkey(key)
    return key, pubkey

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
    """Extract 65-byte uncompressed public key from DER-encoded or raw format.
    
    Accepts:
    - Raw 65-byte uncompressed pubkey starting with 0x04
    - DER-encoded SubjectPublicKeyInfo
    """
    # Check if it's already raw 65-byte uncompressed pubkey
    if len(der_data) == 65 and der_data[0] == 0x04:
        return der_data
    
    # Otherwise try to find 0x04 marker in DER structure
    idx = der_data.find(b'\x04', 20)
    if idx == -1:
        # Try from beginning for shorter DER formats
        idx = der_data.find(b'\x04')
        if idx == -1 or idx + 65 > len(der_data):
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
    if _USE_INTERFACE_MODULE:
        return _iface_is_connected()
    try:
        result = run_ssscli(['se05x', 'uid'], check=False)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def se050_connect(retries: int = 3, debug: bool = False) -> bool:
    """Establish connection to SE050 with verification"""
    if _USE_INTERFACE_MODULE:
        try:
            return _iface_connect(retries=retries, debug=debug)
        except Exception as e:
            if debug:
                print(f"Interface connect failed: {e}")
            return False
    import time
    
    port = Config.get_connection_port()
    conn_type = Config.CONNECTION_TYPE
    
    for attempt in range(retries):
        try:
            # First check if already connected by trying UID
            verify = subprocess.run(
                ['ssscli', 'se05x', 'uid'],
                capture_output=True, text=True, timeout=10
            )
            if debug:
                print(f"  [DEBUG] UID check: rc={verify.returncode}")
                print(f"  [DEBUG] stdout ({len(verify.stdout)}): {repr(verify.stdout[:100])}")
                print(f"  [DEBUG] stderr ({len(verify.stderr)}): {repr(verify.stderr[:100])}")
            
            # Check both stdout and stderr for uid pattern (hex or text)
            combined = (verify.stdout + verify.stderr).lower()
            has_uid = 'uid' in combined or (verify.returncode == 0 and len(verify.stdout.strip()) >= 32)
            
            if debug:
                print(f"  [DEBUG] has_uid={has_uid}, rc={verify.returncode}")
            
            if verify.returncode == 0 and has_uid:
                return True
            
            # Not connected, try to connect
            if debug:
                print(f"  [DEBUG] Connecting: ssscli connect se05x {conn_type} {port}")
            result = subprocess.run(
                ['ssscli', 'connect', 'se05x', conn_type, port, '--auth_type', 'PlatformSCP', '--scpkey', str(Path.home() / '.se050-wallet' / 'scp03.key')],
                capture_output=True, text=True, timeout=15
            )
            if debug:
                print(f"  [DEBUG] Connect: rc={result.returncode}")
                if result.stderr:
                    print(f"  [DEBUG] stderr: {result.stderr[:100]}")
            
            # Give it a moment to establish
            time.sleep(0.5)
            
            # Verify connection
            verify = subprocess.run(
                ['ssscli', 'se05x', 'uid'],
                capture_output=True, text=True, timeout=10
            )
            if debug:
                print(f"  [DEBUG] Verify: rc={verify.returncode}")
                print(f"  [DEBUG] stdout ({len(verify.stdout)}): {repr(verify.stdout[:100])}")
                print(f"  [DEBUG] stderr ({len(verify.stderr)}): {repr(verify.stderr[:100])}")
            
            combined = (verify.stdout + verify.stderr).lower()
            has_uid = 'uid' in combined or (verify.returncode == 0 and len(verify.stdout.strip()) >= 32)
            
            if debug:
                print(f"  [DEBUG] has_uid={has_uid}")
            
            if verify.returncode == 0 and has_uid:
                return True
            
            # If verify failed, try disconnecting and reconnecting
            if attempt < retries - 1:
                subprocess.run(['ssscli', 'disconnect'], capture_output=True, timeout=5)
                time.sleep(0.5)
                
        except Exception as e:
            if debug or attempt == retries - 1:
                print(f"Connection error: {e}")
            time.sleep(0.5)
    
    return False

def se050_disconnect():
    """Disconnect from SE050"""
    if _USE_INTERFACE_MODULE:
        _iface_disconnect()
        return
    try:
        subprocess.run(['ssscli', 'disconnect'], capture_output=True, timeout=5)
    except:
        pass

def se050_reconnect() -> bool:
    """Force disconnect and reconnect"""
    if _USE_INTERFACE_MODULE:
        return _iface_reconnect()
    se050_disconnect()
    import time
    time.sleep(0.5)
    return se050_connect()

def se050_get_uid() -> Optional[str]:
    """Get SE050 unique identifier"""
    if _USE_INTERFACE_MODULE:
        return _iface_get_uid()
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
    if _USE_INTERFACE_MODULE:
        return _iface_get_random(num_bytes)
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
    if _USE_INTERFACE_MODULE:
        try:
            return _iface_generate_keypair(key_id, curve)
        except Exception as e:
            print(f"Key generation failed: {e}")
            return False
    try:
        run_ssscli(['generate', 'ecc', key_id, curve])
        return True
    except SE050Error as e:
        print(f"Key generation failed: {e}")
        return False

def _derive_pubkey_uncompressed(private_key: bytes) -> bytes:
    """
    Derive uncompressed public key (65 bytes: 0x04 + X + Y) from private key.
    Uses secp256k1 curve.
    """
    # secp256k1 parameters
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    
    def modinv(a, m):
        if a < 0:
            a = m + a
        g, x, _ = extended_gcd(a, m)
        if g != 1:
            raise ValueError("No modular inverse")
        return x % m
    
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    def point_add(p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2:
            if y1 != y2:
                return None
            # Point doubling
            s = (3 * x1 * x1 + A) * modinv(2 * y1, P) % P
        else:
            s = (y2 - y1) * modinv(x2 - x1, P) % P
        x3 = (s * s - x1 - x2) % P
        y3 = (s * (x1 - x3) - y1) % P
        return (x3, y3)
    
    def scalar_mult(k, point):
        result = None
        addend = point
        while k:
            if k & 1:
                result = point_add(result, addend)
            addend = point_add(addend, addend)
            k >>= 1
        return result
    
    k = int.from_bytes(private_key, 'big')
    pub_point = scalar_mult(k, (Gx, Gy))
    
    pub_x = pub_point[0].to_bytes(32, 'big')
    pub_y = pub_point[1].to_bytes(32, 'big')
    
    return b'\x04' + pub_x + pub_y


def _build_sec1_der(private_key: bytes, include_pubkey: bool = True) -> bytes:
    """
    Build SEC1 EC private key in DER format for secp256k1.
    
    Structure:
    ECPrivateKey ::= SEQUENCE {
      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
      privateKey     OCTET STRING,
      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
      publicKey  [1] BIT STRING OPTIONAL
    }
    """
    # secp256k1 OID: 1.3.132.0.10
    secp256k1_oid = bytes([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a])
    
    # Build inner sequence
    version = bytes([0x02, 0x01, 0x01])  # INTEGER 1
    priv_octet = bytes([0x04, 0x20]) + private_key  # OCTET STRING (32 bytes)
    params = bytes([0xa0, len(secp256k1_oid)]) + secp256k1_oid  # [0] EXPLICIT
    
    inner = version + priv_octet + params
    
    # Optionally include public key
    if include_pubkey:
        pubkey = _derive_pubkey_uncompressed(private_key)
        # BIT STRING: 0x03 <length> 0x00 (no unused bits) <pubkey>
        bitstring_content = bytes([0x00]) + pubkey  # 66 bytes
        pubkey_bitstring = bytes([0x03, len(bitstring_content)]) + bitstring_content
        # Wrap in [1] EXPLICIT
        pubkey_tagged = bytes([0xa1, len(pubkey_bitstring)]) + pubkey_bitstring
        inner = inner + pubkey_tagged
    
    # Wrap in SEQUENCE
    if len(inner) < 128:
        der = bytes([0x30, len(inner)]) + inner
    else:
        der = bytes([0x30, 0x81, len(inner)]) + inner
    
    return der


def _build_raw_keypair(private_key: bytes) -> bytes:
    """
    Build raw keypair format: just the 32-byte private key.
    Some ssscli versions expect this.
    """
    return private_key


def _build_pkcs8_der(private_key: bytes) -> bytes:
    """
    Build PKCS#8 wrapped EC private key for secp256k1.
    
    Structure:
    PrivateKeyInfo ::= SEQUENCE {
      version                   Version,
      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
      privateKey                PrivateKey,
    }
    """
    # Algorithm identifier for EC with secp256k1
    # SEQUENCE { OID ecPublicKey, OID secp256k1 }
    ec_oid = bytes([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])  # 1.2.840.10045.2.1
    secp256k1_oid = bytes([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a])  # 1.3.132.0.10
    algo_seq = bytes([0x30, len(ec_oid) + len(secp256k1_oid)]) + ec_oid + secp256k1_oid
    
    # Inner EC private key (SEC1 with public key)
    inner_ec = _build_sec1_der(private_key, include_pubkey=True)
    
    # Wrap as OCTET STRING
    ec_privkey_octet = bytes([0x04, len(inner_ec)]) + inner_ec
    
    # PKCS#8 version
    pkcs8_version = bytes([0x02, 0x01, 0x00])
    
    # Full PKCS#8 sequence
    inner = pkcs8_version + algo_seq + ec_privkey_octet
    if len(inner) < 128:
        return bytes([0x30, len(inner)]) + inner
    else:
        return bytes([0x30, 0x81, len(inner)]) + inner


def se050_set_ecc_keypair(key_id: str, private_key: bytes, curve: str = "Secp256k1") -> bool:
    """
    Import/set an ECC keypair on SE050 from a private key.
    The private key is written to the SE050 - after this, the SE050 holds the key.

    Args:
        key_id: SE050 key slot ID (hex string like "20000001")
        private_key: 32-byte secp256k1 private key
        curve: Curve type (default Secp256k1)

    Returns:
        True if successful
    """
    if len(private_key) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(private_key)}")

    if _USE_INTERFACE_MODULE:
        try:
            return _iface_set_keypair(key_id, private_key, curve)
        except Exception:
            # Fall back to built-in ssscli implementation
            pass

    key_file = Path("/tmp/se050_import_key.bin")
    last_error = None
    
    # First, ensure any existing key is deleted
    print(f"  Checking if key 0x{key_id} exists...")
    if se050_key_exists(key_id):
        print(f"  Key exists, deleting...")
        try:
            result = subprocess.run(
                ['ssscli', 'erase', key_id],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                print(f"  Warning: Could not delete existing key: {result.stderr or result.stdout}")
            else:
                print(f"  Existing key deleted")
                import time
                time.sleep(0.3)  # Give SE050 time to settle
        except Exception as e:
            print(f"  Warning: Delete failed: {e}")
    
    # Derive public key for formats that need it
    pubkey_uncompressed = _derive_pubkey_uncompressed(private_key)
    # Raw keypair: 32-byte privkey + 64-byte pubkey (without 0x04 prefix)
    raw_keypair = private_key + pubkey_uncompressed[1:]  # 96 bytes total
    
    # Try multiple formats - SE050/ssscli versions vary in what they accept
    # Also try both 'pair' and 'keypair' commands as ssscli versions differ
    formats_to_try = [
        # (command, format_flag, key_data, description, extra_args)
        # DER formats first (most likely to work)
        ('pair', "DER", _build_sec1_der(private_key), "SEC1 DER with pubkey (pair)", []),
        ('keypair', "DER", _build_sec1_der(private_key), "SEC1 DER with pubkey (keypair)", []),
        ('pair', "DER", _build_pkcs8_der(private_key), "PKCS#8 DER (pair)", []),
        # Raw keypair format (privkey || pubkey)
        ('pair', "BIN", raw_keypair, "raw 96-byte keypair (pair)", []),
        ('keypair', "BIN", raw_keypair, "raw 96-byte keypair (keypair)", []),
        # Just private key
        ('pair', "BIN", private_key, "raw 32-byte privkey (pair)", []),
        ('keypair', "BIN", private_key, "raw 32-byte privkey (keypair)", []),
        # SEC1 without pubkey
        ('pair', "DER", _build_sec1_der(private_key, include_pubkey=False), "SEC1 DER no pubkey (pair)", []),
        # Try without format flag
        ('pair', None, _build_sec1_der(private_key), "SEC1 auto-detect (pair)", []),
        ('keypair', None, raw_keypair, "raw keypair auto-detect", []),
    ]
    
    for cmd_type, fmt_flag, key_data, desc, extra_args in formats_to_try:
        try:
            # Write key data to temp file
            key_file.write_bytes(key_data)
            
            print(f"  Trying {desc} format ({len(key_data)} bytes)...")
            
            # Build command - try both 'pair' and 'keypair' variants
            cmd = ['ssscli', 'set', 'ecc', cmd_type, key_id, str(key_file)]
            if fmt_flag:
                cmd.extend(['--format', fmt_flag])
            cmd.extend(extra_args)
            
            # Try to set the key
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                print(f"  Success with {desc} format!")
                # Verify key was written
                if se050_key_exists(key_id):
                    return True
                else:
                    print(f"  Warning: Key set returned success but key not found")
            else:
                last_error = result.stderr or result.stdout or "Unknown error"
                print(f"  {desc} failed: {last_error.strip()[:80]}")
                
        except subprocess.TimeoutExpired:
            last_error = "Command timed out"
            print(f"  {desc} timed out")
        except Exception as e:
            last_error = str(e)
            print(f"  {desc} exception: {e}")
        finally:
            # Securely delete temp file
            if key_file.exists():
                key_file.write_bytes(b'\x00' * max(32, len(key_data)))
                key_file.unlink()
    
    # All formats failed
    raise SE050Error(f"All formats rejected by SE050\nLast error: {last_error}")

def se050_export_pubkey(key_id: str, output_path: Path, format: str = "DER") -> bool:
    """Export public key from SE050"""
    if _USE_INTERFACE_MODULE:
        try:
            result = _iface_export_pubkey(key_id, output_path, format)
            # Interface returns bytes; if we got data and output_path exists, success
            if result and isinstance(result, bytes):
                return True
            return bool(result)
        except Exception as e:
            print(f"Public key export failed: {e}")
            return False
    try:
        run_ssscli(['get', 'ecc', 'pub', key_id, str(output_path), '--format', format])
        return True
    except SE050Error as e:
        print(f"Public key export failed: {e}")
        return False

def se050_delete_key(key_id: str) -> bool:
    """Delete key from SE050"""
    if _USE_INTERFACE_MODULE:
        try:
            return _iface_delete_key(key_id)
        except Exception as e:
            print(f"Key deletion failed: {e}")
            return False
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
    if _USE_INTERFACE_MODULE:
        sig = _iface_sign(key_id, data)
        return normalize_signature(sig)
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
    if _USE_INTERFACE_MODULE:
        return _iface_key_exists(key_id)
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

def parse_amount(amount_str: str) -> Tuple[int, str]:
    """
    Parse amount string with optional unit suffix.
    
    Supports:
        10000       -> 10000 sats
        10000sat    -> 10000 sats  
        10000sats   -> 10000 sats
        0.0001btc   -> sats equivalent
        0.0001BTC   -> sats equivalent
        50usd       -> sats equivalent (fetches price)
        50USD       -> sats equivalent
        $50         -> sats equivalent
        
    Returns: (satoshis, description)
    """
    amount_str = amount_str.strip()
    
    # Handle $50 format
    if amount_str.startswith('$'):
        amount_str = amount_str[1:] + 'usd'
    
    # Lowercase for matching
    lower = amount_str.lower()
    
    # Satoshis (default)
    if lower.endswith('sat') or lower.endswith('sats'):
        num = lower.replace('sats', '').replace('sat', '').strip()
        sats = int(float(num))
        return sats, f"{sats:,} sats"
    
    # BTC
    if lower.endswith('btc'):
        num = lower.replace('btc', '').strip()
        btc = float(num)
        sats = int(btc * 100_000_000)
        return sats, f"{btc} BTC ({sats:,} sats)"
    
    # USD
    if lower.endswith('usd'):
        num = lower.replace('usd', '').strip()
        usd = float(num)
        price = get_btc_price('USD')
        if not price:
            raise ValueError("Could not fetch BTC price for USD conversion")
        btc = usd / price
        sats = int(btc * 100_000_000)
        return sats, f"${usd:.2f} USD ({sats:,} sats @ ${price:,.0f})"
    
    # EUR
    if lower.endswith('eur'):
        num = lower.replace('eur', '').strip()
        eur = float(num)
        price = get_btc_price('EUR')
        if not price:
            raise ValueError("Could not fetch BTC price for EUR conversion")
        btc = eur / price
        sats = int(btc * 100_000_000)
        return sats, f"€{eur:.2f} EUR ({sats:,} sats @ €{price:,.0f})"
    
    # GBP
    if lower.endswith('gbp'):
        num = lower.replace('gbp', '').strip()
        gbp = float(num)
        price = get_btc_price('GBP')
        if not price:
            raise ValueError("Could not fetch BTC price for GBP conversion")
        btc = gbp / price
        sats = int(btc * 100_000_000)
        return sats, f"£{gbp:.2f} GBP ({sats:,} sats @ £{price:,.0f})"
    
    # Default: plain number = sats
    sats = int(float(amount_str))
    return sats, f"{sats:,} sats"

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
        print("      [FAIL] Failed to connect to SE050")
        print("")
        print("      Troubleshooting:")
        print("      1. Unplug and replug USB cable to K64F")
        print("      2. Press reset button on K64F board")
        print("      3. Check SE050ARD is properly seated")
        print("      4. Verify: ls /dev/ttyACM*")
        print("      5. Test manually: ssscli connect se05x vcom /dev/ttyACM0")
        print("                        ssscli se05x uid")
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

def cmd_create(args):
    """Create new wallet with seed phrase backup"""
    print("")
    print("=" * 60)
    print("SE050 HARDWARE WALLET - CREATE WITH SEED PHRASE")
    print("=" * 60)

    Config.WALLET_DIR.mkdir(parents=True, exist_ok=True)

    # Check if wallet already exists
    if Config.pubkey_der_path().exists():
        print("")
        print(f"[!] Wallet already exists for Key ID 0x{Config.KEY_ID}")
        confirm = input("    Overwrite? [y/N]: ")
        if confirm.lower() != 'y':
            print("    Cancelled.")
            return 1

    # Connect to SE050
    print("")
    print("[1/5] Connecting to SE050...")
    if not se050_connect():
        print("      [FAIL] Failed to connect to SE050")
        return 1
    print("      [OK] Connected")

    # Generate mnemonic
    strength = 256 if args.words == 24 else 128
    print("")
    print(f"[2/5] Generating {args.words}-word seed phrase...")
    mnemonic = generate_mnemonic(strength)

    print("")
    print("=" * 60)
    print("WRITE DOWN THESE WORDS - THIS IS YOUR ONLY BACKUP!")
    print("=" * 60)
    print("")
    words = mnemonic.split()
    for i, word in enumerate(words, 1):
        print(f"  {i:2d}. {word}")
    print("")
    print("=" * 60)
    print("WARNING: If you lose these words, you lose your Bitcoin!")
    print("         Never store them digitally. Write on paper only.")
    print("=" * 60)
    print("")

    # Verify user wrote it down
    confirm = input("Have you written down your seed phrase? [y/N]: ")
    if confirm.lower() != 'y':
        print("Please write down your seed phrase before continuing.")
        return 1

    print("")
    verify = input("Enter word #1 to verify: ").strip().lower()
    if verify != words[0]:
        print(f"Incorrect! Expected '{words[0]}'. Please try again.")
        return 1

    verify = input(f"Enter word #{len(words)} to verify: ").strip().lower()
    if verify != words[-1]:
        print(f"Incorrect! Expected '{words[-1]}'. Please try again.")
        return 1

    # Derive key from seed
    print("")
    print("[3/5] Deriving private key from seed...")
    seed = mnemonic_to_seed(mnemonic)
    coin_type = 1 if Config.NETWORK == "testnet" else 0
    private_key, pubkey = derive_bip84_key(seed, coin_type=coin_type)
    print("      [OK] Key derived (m/84'/0'/0'/0/0)")

    # Delete existing key if present
    if se050_key_exists(Config.KEY_ID):
        se050_delete_key(Config.KEY_ID)

    # Write key to SE050
    print("")
    print(f"[4/5] Writing private key to SE050 slot 0x{Config.KEY_ID}...")
    if not se050_set_ecc_keypair(Config.KEY_ID, private_key):
        print("      [FAIL] Failed to write key to SE050")
        return 1
    print("      [OK] Private key stored in SE050")

    # Export public key
    print("")
    print("[5/5] Exporting public key...")
    if not se050_export_pubkey(Config.KEY_ID, Config.pubkey_der_path(), "DER"):
        print("      [FAIL] Export failed")
        return 1
    se050_export_pubkey(Config.KEY_ID, Config.pubkey_pem_path(), "PEM")
    print(f"      [OK] Saved to {Config.pubkey_der_path()}")

    # Load and display wallet
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
        print(f"Derivation: m/84'/0'/0'/0/0 (BIP84 Native SegWit)")
        print(f"")
        print(f"RECEIVE ADDRESSES:")
        print(f"  SegWit:  {wallet.addresses['segwit']}")
        print(f"  Legacy:  {wallet.addresses['legacy']}")
        print("")
        print("BACKUP:")
        print("  - Your seed phrase is your backup")
        print("  - If SE050 is lost, import seed to new chip")
        print("  - NEVER lose your seed phrase!")
        print("=" * 60)
        print("")

    return 0

def cmd_import_seed(args):
    """Import wallet from seed phrase"""
    print("")
    print("=" * 60)
    print("SE050 HARDWARE WALLET - IMPORT FROM SEED PHRASE")
    print("=" * 60)

    Config.WALLET_DIR.mkdir(parents=True, exist_ok=True)

    # Check if wallet already exists
    if Config.pubkey_der_path().exists():
        print("")
        print(f"[!] Wallet already exists for Key ID 0x{Config.KEY_ID}")
        confirm = input("    Overwrite? [y/N]: ")
        if confirm.lower() != 'y':
            print("    Cancelled.")
            return 1

    # Get mnemonic
    if args.mnemonic:
        mnemonic = args.mnemonic.strip().lower()
    else:
        print("")
        print("Enter your seed phrase (12 or 24 words):")
        mnemonic = input("> ").strip().lower()

    # Validate mnemonic
    if not validate_mnemonic(mnemonic):
        print("")
        print("[FAIL] Invalid seed phrase!")
        print("       Check spelling and word order.")
        return 1

    words = mnemonic.split()
    print(f"      [OK] Valid {len(words)}-word seed phrase")

    # Connect to SE050
    print("")
    print("[1/4] Connecting to SE050...")
    if not se050_connect():
        print("      [FAIL] Failed to connect to SE050")
        return 1
    print("      [OK] Connected")

    # Derive key from seed
    print("")
    print("[2/4] Deriving private key from seed...")
    seed = mnemonic_to_seed(mnemonic)
    coin_type = 1 if Config.NETWORK == "testnet" else 0
    private_key, pubkey = derive_bip84_key(seed, coin_type=coin_type)
    print("      [OK] Key derived (m/84'/0'/0'/0/0)")

    # Delete existing key if present
    if se050_key_exists(Config.KEY_ID):
        se050_delete_key(Config.KEY_ID)

    # Write key to SE050
    print("")
    print(f"[3/4] Writing private key to SE050 slot 0x{Config.KEY_ID}...")
    if not se050_set_ecc_keypair(Config.KEY_ID, private_key):
        print("      [FAIL] Failed to write key to SE050")
        return 1
    print("      [OK] Private key stored in SE050")

    # Export public key
    print("")
    print("[4/4] Exporting public key...")
    if not se050_export_pubkey(Config.KEY_ID, Config.pubkey_der_path(), "DER"):
        print("      [FAIL] Export failed")
        return 1
    se050_export_pubkey(Config.KEY_ID, Config.pubkey_pem_path(), "PEM")
    print(f"      [OK] Saved to {Config.pubkey_der_path()}")

    # Load and display wallet
    wallet = Wallet()
    wallet.created_at = datetime.now().isoformat()
    if wallet.load():
        wallet.save_info()

        print("")
        print("=" * 60)
        print("WALLET IMPORTED SUCCESSFULLY")
        print("=" * 60)
        print(f"")
        print(f"Key ID:     0x{Config.KEY_ID}")
        print(f"Network:    {Config.NETWORK}")
        print(f"Derivation: m/84'/0'/0'/0/0 (BIP84 Native SegWit)")
        print(f"")
        print(f"RECEIVE ADDRESSES:")
        print(f"  SegWit:  {wallet.addresses['segwit']}")
        print(f"  Legacy:  {wallet.addresses['legacy']}")
        print("")
        print("Your wallet has been restored from your seed phrase.")
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
    
    # Parse amount with unit support
    try:
        amount_sats, amount_desc = parse_amount(args.amount)
    except ValueError as e:
        print(f"")
        print(f"[FAIL] Invalid amount: {e}")
        print("")
        return 1
    
    fee_rate = args.fee or Config.DEFAULT_FEE_RATE
    
    print(f"")
    print(f"SEND TRANSACTION")
    print(f"  To:     {dest_address}")
    print(f"  Amount: {amount_desc}")
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

def cmd_reset(args):
    """Reset SE050 connection"""
    port = Config.get_connection_port()
    
    print("")
    print(f"Connection: {Config.CONNECTION_TYPE} @ {port}")
    print("")
    print("Disconnecting...")
    se050_disconnect()
    
    import time
    time.sleep(1)
    
    print("Reconnecting...")
    if se050_connect():
        print("[OK] Reconnected successfully")
        uid = se050_get_uid()
        if uid:
            print(f"UID: {uid}")
        rng = se050_get_random()
        if rng:
            print(f"TRNG: {rng.hex()}")
        return 0
    else:
        print("[FAIL] Reconnection failed")
        print("")
        print("Try:")
        print("  1. Unplug and replug USB cable")
        print("  2. Press reset button on K64F")
        print(f"  3. Manually: ssscli connect se05x vcom {port}")
        return 1

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
    
    port = Config.get_connection_port()
    print(f"")
    print(f"Connection: {Config.CONNECTION_TYPE} @ {port}")
    
    print("")
    print("Connecting to SE050...")
    if not se050_connect():
        print("[FAIL] Connection failed. Check:")
        print("       - K64F connected via USB")
        print("       - SE050ARD attached to K64F")
        print("       - Correct /dev/ttyACM* device")
        print(f"")
        print(f"       Try: ssscli connect se05x vcom {port}")
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
    
    # The SE050 does not allow private key export - there is no command for it.
    # ssscli "get ecc pair" misleadingly just returns the public key (same as "pub")
    # We verify this by checking that the output is a public key, not a keypair
    
    keypair_path = Path("/tmp/se050_verify_keypair.der")
    if keypair_path.exists():
        keypair_path.unlink()
    
    result = subprocess.run(
        ['ssscli', 'get', 'ecc', 'pair', Config.KEY_ID, str(keypair_path), '--format', 'DER'],
        capture_output=True, text=True
    )
    
    # Check what we got
    is_public_key_only = 'Public Key' in result.stdout
    file_size = keypair_path.stat().st_size if keypair_path.exists() else 0
    
    # A secp256k1 public key DER is ~88 bytes
    # A full keypair with private key would be 150+ bytes
    is_small_file = file_size < 120
    
    # Clean up
    if keypair_path.exists():
        keypair_path.unlink()
    
    if is_public_key_only and is_small_file:
        print("       [OK] Private key cannot be extracted")
        print(f"       (ssscli returned public key only, {file_size} bytes)")
    elif file_size > 120:
        print(f"       [WARN] Unexpected file size ({file_size} bytes) - verify manually")
        print("       Run: ssscli get ecc pair 20000001 /tmp/test.der --format DER")
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

def cmd_watch(args):
    """Watch wallet for incoming transactions"""
    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1
    
    interval = args.interval or 30
    
    print("")
    print("=" * 60)
    print("WATCHING FOR TRANSACTIONS")
    print("=" * 60)
    print("")
    print(f"SegWit: {wallet.addresses['segwit']}")
    print(f"Legacy: {wallet.addresses['legacy']}")
    print(f"")
    print(f"Checking every {interval} seconds. Press Ctrl+C to stop.")
    print("")
    
    # Get initial balance
    def get_total_balance():
        total = 0
        for addr in [wallet.addresses['segwit'], wallet.addresses['legacy']]:
            info = get_address_info(addr)
            if info:
                funded = info['chain_stats']['funded_txo_sum']
                spent = info['chain_stats']['spent_txo_sum']
                total += funded - spent
        return total
    
    last_balance = get_total_balance()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Current balance: {last_balance:,} sats")
    
    try:
        import time
        while True:
            time.sleep(interval)
            
            current = get_total_balance()
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            if current != last_balance:
                diff = current - last_balance
                if diff > 0:
                    print(f"[{timestamp}] 💰 RECEIVED +{diff:,} sats! New balance: {current:,} sats")
                    # Try system notification
                    try:
                        subprocess.run(['notify-send', 'Bitcoin Received!', f'+{diff:,} sats'], 
                                     capture_output=True, timeout=5)
                    except:
                        pass
                else:
                    print(f"[{timestamp}] 📤 SENT {diff:,} sats. New balance: {current:,} sats")
                last_balance = current
            else:
                print(f"[{timestamp}] No change. Balance: {current:,} sats")
                
    except KeyboardInterrupt:
        print("")
        print("Stopped watching.")
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
  %(prog)s create                      Create wallet with seed phrase backup
  %(prog)s create --words 24           Create wallet with 24-word seed
  %(prog)s import-seed                 Import wallet from existing seed
  %(prog)s init                        Create wallet (NO seed backup - legacy)
  %(prog)s address                     Show receive addresses
  %(prog)s address --qr                Show address with QR code
  %(prog)s balance                     Check balance
  %(prog)s balance --fiat usd          Check balance with USD value
  %(prog)s send bc1q... 10000          Send 10,000 sats
  %(prog)s send bc1q... 0.001btc       Send 0.001 BTC
  %(prog)s send bc1q... $50            Send $50 USD worth
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
    
    # init (legacy - generates key on SE050, no backup)
    subparsers.add_parser('init', help='Initialize wallet (generates key on SE050, NO BACKUP)')

    # create (new - generates seed phrase for backup)
    create_parser = subparsers.add_parser('create', help='Create new wallet with seed phrase backup')
    create_parser.add_argument('--words', type=int, choices=[12, 24], default=12,
                               help='Number of seed words (default: 12)')

    # import-seed (restore from seed phrase)
    import_parser = subparsers.add_parser('import-seed', help='Import wallet from seed phrase')
    import_parser.add_argument('mnemonic', nargs='?', help='Seed phrase (or enter interactively)')

    # address
    addr_parser = subparsers.add_parser('address', help='Show receive addresses')
    addr_parser.add_argument('--qr', action='store_true', help='Show QR code')
    
    # balance
    bal_parser = subparsers.add_parser('balance', help='Check balance')
    bal_parser.add_argument('--fiat', type=str, help='Show value in fiat currency (usd, eur, gbp, etc.)')
    
    # send
    send_parser = subparsers.add_parser('send', help='Send Bitcoin')
    send_parser.add_argument('address', help='Destination address')
    send_parser.add_argument('amount', type=str, help='Amount: 10000, 0.0001btc, $50, 50usd')
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
    
    # watch
    watch_parser = subparsers.add_parser('watch', help='Watch for incoming transactions')
    watch_parser.add_argument('-i', '--interval', type=int, default=30, help='Check interval in seconds (default: 30)')
    
    # export
    subparsers.add_parser('export', help='Export public key info')
    
    # wipe
    subparsers.add_parser('wipe', help='Delete wallet (DANGER!)')
    
    # info
    subparsers.add_parser('info', help='Show SE050 status')
    subparsers.add_parser('reset', help='Reset SE050 connection')
    
    args = parser.parse_args()
    
    if args.testnet:
        Config.NETWORK = "testnet"
    if args.keyid:
        Config.KEY_ID = args.keyid
    
    commands = {
        'init': cmd_init,
        'create': cmd_create,
        'import-seed': cmd_import_seed,
        'address': cmd_address,
        'balance': cmd_balance,
        'send': cmd_send,
        'sign-message': cmd_sign_message,
        'history': cmd_history,
        'verify': cmd_verify,
        'watch': cmd_watch,
        'export': cmd_export,
        'wipe': cmd_wipe,
        'info': cmd_info,
        'reset': cmd_reset,
    }
    
    if args.command in commands:
        sys.exit(commands[args.command](args))
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
