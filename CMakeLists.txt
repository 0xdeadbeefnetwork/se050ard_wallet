#
# SE050 Hardware Wallet C Library
# 
# Builds a self-contained shared library with all NXP middleware
# statically linked. No runtime dependencies on middleware.
#
# Copyright 2025 _SiCk @ afflicted.sh
# SPDX-License-Identifier: MIT
#

cmake_minimum_required(VERSION 3.10)
project(se050_wallet VERSION 1.0.0 LANGUAGES C)

option(SE050_WALLET_DEBUG "Enable debug output" OFF)

# Find NXP Plug & Trust Middleware
if(NOT DEFINED SIMW_TOP_DIR)
    # Check environment variable first
    if(DEFINED ENV{SIMW_TOP_DIR})
        set(SIMW_TOP_DIR "$ENV{SIMW_TOP_DIR}")
    # Then common locations
    elseif(EXISTS "$ENV{HOME}/puzzle/simw-top")
        set(SIMW_TOP_DIR "$ENV{HOME}/puzzle/simw-top")
    elseif(EXISTS "$ENV{HOME}/simw-top")
        set(SIMW_TOP_DIR "$ENV{HOME}/simw-top")
    elseif(EXISTS "/opt/nxp/simw-top")
        set(SIMW_TOP_DIR "/opt/nxp/simw-top")
    elseif(EXISTS "/opt/simw-top")
        set(SIMW_TOP_DIR "/opt/simw-top")
    else()
        message(FATAL_ERROR 
            "NXP middleware not found!\n"
            "Set SIMW_TOP_DIR to your middleware path:\n"
            "  cmake .. -DSIMW_TOP_DIR=/path/to/simw-top\n"
            "Or set environment variable:\n"
            "  export SIMW_TOP_DIR=/path/to/simw-top"
        )
    endif()
endif()

set(SIMW_BUILD_DIR ${SIMW_TOP_DIR}/build)

if(NOT EXISTS "${SIMW_BUILD_DIR}")
    message(FATAL_ERROR "Middleware not built at ${SIMW_BUILD_DIR}")
endif()

message(STATUS "Using middleware: ${SIMW_TOP_DIR}")

# ============================================================================
# Include directories
# ============================================================================
set(SIMW_INC_DIRS
    ${SIMW_BUILD_DIR}                                    # fsl_sss_ftr.h
    ${SIMW_TOP_DIR}/sss/inc
    ${SIMW_TOP_DIR}/sss/ex/inc
    ${SIMW_TOP_DIR}/sss/ex/src
    ${SIMW_TOP_DIR}/sss/port/default
    ${SIMW_TOP_DIR}/hostlib/hostLib/inc
    ${SIMW_TOP_DIR}/hostlib/hostLib/se05x_03_xx_xx
    ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/infra
    ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/log
    ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/smCom
    ${SIMW_TOP_DIR}/hostlib/hostLib/libCommon/scp
    ${SIMW_TOP_DIR}/hostlib/hostLib/platform/inc
    ${SIMW_TOP_DIR}/ext/mbedtls/include
)

# ============================================================================
# Static libraries from middleware build (order matters for linking!)
# ============================================================================
set(MW_STATIC_LIBS
    ${SIMW_BUILD_DIR}/sss/libSSS_APIs.a
    ${SIMW_BUILD_DIR}/sss/ex/src/libex_common.a
    ${SIMW_BUILD_DIR}/hostlib/hostLib/se05x/libse05x.a
    ${SIMW_BUILD_DIR}/hostlib/hostLib/libCommon/libsmCom.a
    ${SIMW_BUILD_DIR}/hostlib/hostLib/libCommon/log/libmwlog.a
    ${SIMW_BUILD_DIR}/hostlib/hostLib/liba7x_utils.a
    ${SIMW_BUILD_DIR}/ext/libmbedtls.a
)

# Verify all libraries exist
foreach(lib ${MW_STATIC_LIBS})
    if(EXISTS ${lib})
        message(STATUS "  Found: ${lib}")
    else()
        message(FATAL_ERROR "Missing: ${lib}")
    endif()
endforeach()

# ============================================================================
# Build shared library
# ============================================================================
add_library(se050_wallet SHARED src/se050_wallet.c)

set_target_properties(se050_wallet PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "include/se050_wallet.h"
)

target_include_directories(se050_wallet
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${SIMW_INC_DIRS}
)

# Link everything - whole-archive ensures all symbols are included
target_link_libraries(se050_wallet
    PRIVATE
        -Wl,--whole-archive
        ${SIMW_BUILD_DIR}/sss/libSSS_APIs.a
        ${SIMW_BUILD_DIR}/hostlib/hostLib/libCommon/log/libmwlog.a
        ${SIMW_BUILD_DIR}/hostlib/hostLib/liba7x_utils.a
        -Wl,--no-whole-archive
        ${SIMW_BUILD_DIR}/sss/ex/src/libex_common.a
        ${SIMW_BUILD_DIR}/hostlib/hostLib/se05x/libse05x.a
        ${SIMW_BUILD_DIR}/hostlib/hostLib/libCommon/libsmCom.a
        ${SIMW_BUILD_DIR}/ext/libmbedtls.a
        ssl
        crypto
        pthread
        dl
)

target_compile_definitions(se050_wallet PRIVATE
    SSS_USE_FTR_FILE
    T1oI2C
    T1oI2C_UM11225
)

if(SE050_WALLET_DEBUG)
    target_compile_definitions(se050_wallet PRIVATE SE050_WALLET_DEBUG=1)
endif()

target_compile_options(se050_wallet PRIVATE -Wall -Wextra -Wno-unused-parameter)

# ============================================================================
# Install
# ============================================================================
include(GNUInstallDirs)
install(TARGETS se050_wallet
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "SE050 Wallet Library v${PROJECT_VERSION}")
message(STATUS "  Middleware: ${SIMW_TOP_DIR}")
message(STATUS "  Debug:      ${SE050_WALLET_DEBUG}")
message(STATUS "")
