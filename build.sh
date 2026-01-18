#!/bin/bash
#
# Build SE050 Wallet Native Library
#
# This builds libse050_wallet.so which provides fast native
# access to SE050 via NXP middleware with SCP03 encryption.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "SE050 Wallet Native Library Build"
echo "=============================================="
echo ""

# Find middleware - check multiple locations
if [ -n "$SIMW_TOP_DIR" ]; then
    SIMW_TOP="$SIMW_TOP_DIR"
elif [ -d "$HOME/puzzle/simw-top" ]; then
    SIMW_TOP="$HOME/puzzle/simw-top"
elif [ -d "$HOME/simw-top" ]; then
    SIMW_TOP="$HOME/simw-top"
elif [ -d "/opt/nxp/simw-top" ]; then
    SIMW_TOP="/opt/nxp/simw-top"
elif [ -d "/opt/simw-top" ]; then
    SIMW_TOP="/opt/simw-top"
else
    echo "ERROR: NXP Plug & Trust middleware not found!"
    echo ""
    echo "Please install the middleware first:"
    echo "  git clone https://github.com/NXP/plug-and-trust.git ~/simw-top"
    echo "  cd ~/simw-top && mkdir build && cd build"
    echo "  cmake .. -DPTMW_SE05X_Auth=PlatfSCP03"
    echo "  make -j\$(nproc)"
    echo ""
    echo "Or set SIMW_TOP_DIR environment variable:"
    echo "  export SIMW_TOP_DIR=/path/to/simw-top"
    exit 1
fi

# Check middleware is built
if [ ! -d "$SIMW_TOP/build" ]; then
    echo "ERROR: Middleware source found at $SIMW_TOP but not built!"
    echo ""
    echo "Build it first:"
    echo "  cd $SIMW_TOP && mkdir -p build && cd build"
    echo "  cmake .. -DPTMW_SE05X_Auth=PlatfSCP03"
    echo "  make -j\$(nproc)"
    exit 1
fi

# Check SCP03 auth is enabled
if grep -q "SSS_HAVE_SE05X_AUTH_PLATFSCP03 1" "$SIMW_TOP/build/fsl_sss_ftr.h" 2>/dev/null; then
    echo "✓ Middleware has SCP03 support"
else
    echo "⚠ WARNING: Middleware may not have SCP03 enabled!"
    echo "  Rebuild with: cd $SIMW_TOP/build && cmake .. -DPTMW_SE05X_Auth=PlatfSCP03 && make -j\$(nproc)"
    echo ""
fi

echo "Using middleware: $SIMW_TOP"
echo ""

# Clean and build
rm -rf build
mkdir build && cd build

cmake .. -DSIMW_TOP_DIR="$SIMW_TOP" -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Create symlink for easy discovery
cd "$SCRIPT_DIR"
ln -sf build/libse050_wallet.so libse050_wallet.so

echo ""
echo "=============================================="
echo "Build complete!"
echo "=============================================="
echo ""
echo "Library: $SCRIPT_DIR/build/libse050_wallet.so"
echo "Symlink: $SCRIPT_DIR/libse050_wallet.so"
echo ""
echo "Test with:"
echo "  cd $SCRIPT_DIR/.."
echo "  python3 -c 'from se050_interface import get_backend; print(get_backend())'"
echo ""
