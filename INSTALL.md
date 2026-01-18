# SE050ARD Wallet - Installation Guide

Complete installation for Raspberry Pi (Raspbian/Raspberry Pi OS).

## Prerequisites

### Hardware
- Raspberry Pi (any model with USB)
- NXP SE050ARD evaluation kit
- FRDM-K64F board (comes with SE050ARD)
- Micro-USB cable

### Software
- Raspberry Pi OS (64-bit recommended)
- Python 3.8+

## Step 1: System Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git cmake build-essential libssl-dev \
    python3-pip python3-tk

# Serial port access
sudo usermod -a -G dialout $USER
# Log out and back in for group change!
```

## Step 2: Hardware Setup

1. **Mount SE050ARD** on K64F Arduino headers
2. **Flash K64F** with VCOM firmware (see NXP AN13022)
3. **Connect K64F** to Pi via USB
4. **Verify**: `ls /dev/ttyACM*` should show `/dev/ttyACM0`

## Step 3: NXP Plug & Trust Middleware

```bash
# Clone middleware
cd ~
git clone https://github.com/NXP/plug-and-trust.git simw-top

# Move to /opt (recommended location)
sudo mv simw-top /opt/simw-top
sudo chown -R $USER:$USER /opt/simw-top

# Build with SCP03 + Raspbian support
cd /opt/simw-top
mkdir build && cd build
cmake .. -DPTMW_SE05X_Auth=PlatfSCP03 -DPTMW_Host=Raspbian -DPTMW_SCP=SCP03_SSS
make -j$(nproc)

# Install ssscli
cd /opt/simw-top/pycli/src
pip3 install -e . --break-system-packages
```

## Step 4: Configure SCP03 Keys

```bash
mkdir -p ~/.se050-wallet
chmod 700 ~/.se050-wallet

# Create key file (adjust for your SE050 variant!)
cat > ~/.se050-wallet/scp03.key << 'EOF'
ENC d2db63e7a0a5aed72a6460c4dfdcaf64
MAC 738d5b798ed241b0b24768514bfba95b
DEK 6702dac30942b2c85e7f47b42ced4e7f
EOF

chmod 600 ~/.se050-wallet/scp03.key
```

> ⚠️ Keys vary by SE050 variant. Check NXP docs if connection fails.

## Step 5: Test Middleware

```bash
ssscli disconnect
ssscli connect se05x vcom /dev/ttyACM0 \
    --auth_type PlatformSCP \
    --scpkey ~/.se050-wallet/scp03.key
ssscli se05x uid
```

Expected output (no "Plain channel" warning):
```
04005001113d1cb43d2b19042758d29c1d90
Unique ID: 04005001113d1cb43d2b19042758d29c1d90
```

## Step 6: Install SE050ARD Wallet

```bash
cd ~/
git clone https://github.com/AffictedIntelligence/se050ard_wallet.git
cd se050ard_wallet

# Install Python dependencies
pip3 install -r requirements.txt --break-system-packages

# Make scripts executable
chmod +x wallet.py wallet_gui.py
```

## Step 7: Build Native Library

```bash
cd lib
chmod +x build.sh

# Set middleware path (add to ~/.bashrc for persistence)
export SIMW_TOP_DIR=/opt/simw-top

./build.sh
```

Expected output:
```
✓ Middleware has SCP03 support
...
Build complete!
Library: .../libse050_wallet.so
```

## Step 8: Verify Installation

```bash
cd ~/se050ard_wallet

python3 -c "from se050_interface import get_backend, connect; print(get_backend()); connect()"
```

Expected:
```
native
...
[SE050] Session opened successfully
```

## Step 9: Create Wallet

```bash
# GUI
./wallet_gui.py

# Or CLI
./wallet.py create
```

**⚠️ WRITE DOWN YOUR SEED PHRASE! ⚠️**

## Environment Variables

Add to `~/.bashrc`:

```bash
export SIMW_TOP_DIR=/opt/simw-top
```

## Troubleshooting

### "Permission denied" on /dev/ttyACM0
```bash
sudo usermod -a -G dialout $USER
# Log out and back in
```

### "SCP03 authentication failed"
- Wrong keys for your SE050 variant
- Power cycle SE050 (unplug USB 3 sec)
- Check key file format

### "Backend: ssscli" instead of "native"
```bash
cd lib
rm -rf build
SIMW_TOP_DIR=/opt/simw-top ./build.sh
```

### Build errors
- Ensure cmake options: `-DPTMW_SE05X_Auth=PlatfSCP03 -DPTMW_Host=Raspbian -DPTMW_SCP=SCP03_SSS`
- Check `/opt/simw-top/build/fsl_sss_ftr.h` has `SSS_HAVE_SE05X_AUTH_PLATFSCP03 1`

### GUI errors
```bash
sudo apt install python3-tk
pip3 install pillow qrcode --break-system-packages
```

## Security Notes

1. **Seed phrase** - Store offline securely
2. **SCP03 keys** - Keep `~/.se050-wallet/` secure
3. **Private keys** - Never leave SE050
4. **Pi security** - Enable firewall, keep updated

## Next Steps

- [README.md](README.md) - Usage guide
- Try testnet first: `./wallet_gui.py --testnet`
