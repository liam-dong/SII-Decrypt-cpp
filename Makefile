# ============================================================================
#  SII Decrypt - Makefile (GCC/MinGW-w64, Windows cmd)
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
#  Prerequisites:
#    - MinGW-w64 (g++) on PATH
#    - OpenSSL static lib:  ./libs/openssl/lib/libcrypto.a
#    - zlib static lib:     ./libs/zlib/lib/libz.a
#    - Headers are in:      ./libs/openssl/include/  and  ./libs/zlib/include/
#
#  Targets:
#    mingw32-make all       — build DLL + console program
#    mingw32-make dll       — build sii_decrypt.dll only
#    mingw32-make console   — build sii_decrypt.exe only
#    mingw32-make clean     — remove build artifacts
# ============================================================================

# Use cmd.exe as the shell for all recipes
SHELL = cmd.exe

# --- Toolchain -----------------------------------------------------------

CXX        = g++
STRIP      = strip

# --- Paths ---------------------------------------------------------------

SRC_DIR    = src
INC_DIR    = include
LIBS_DIR   = libs
BUILD_DIR  = build

# OpenSSL (shipped with project)
OPENSSL_DIR = $(LIBS_DIR)/openssl
OPENSSL_INC = $(OPENSSL_DIR)/include
OPENSSL_LIB = $(OPENSSL_DIR)/lib

# zlib (shipped with project)
ZLIB_DIR    = $(LIBS_DIR)/zlib
ZLIB_INC    = $(ZLIB_DIR)/include
ZLIB_LIB    = $(ZLIB_DIR)/lib

# --- Compiler flags ------------------------------------------------------

CXXFLAGS   = -std=c++11 -Wall -Wextra -O2 -fvisibility=hidden
CXXFLAGS  += -I$(INC_DIR) -I$(SRC_DIR)
CXXFLAGS  += -I$(OPENSSL_INC) -I$(ZLIB_INC)

# Linker flags — static link with shipped libraries
LDFLAGS    = -static -L$(OPENSSL_LIB) -L$(ZLIB_LIB)
LDLIBS     = -lcrypto -lz -lws2_32 -lcrypt32 -lgdi32

# DLL flags
DEF_FILE   = $(SRC_DIR)/sii_decrypt.def
DLL_LDFLAGS = -shared -static-libgcc -static-libstdc++ \
              -Wl,$(DEF_FILE) \
              -Wl,--out-implib,$(BUILD_DIR)/libsii_decrypt.a

# --- Source files --------------------------------------------------------

CORE_SRC   = $(SRC_DIR)/sii_core.cpp
DLL_SRC    = $(SRC_DIR)/sii_dll.cpp
CONSOLE_SRC= $(SRC_DIR)/sii_console.cpp

CORE_OBJ   = $(BUILD_DIR)/sii_core.o
DLL_OBJ    = $(BUILD_DIR)/sii_dll.o
CONSOLE_OBJ= $(BUILD_DIR)/sii_console.o

# --- Output targets ------------------------------------------------------

DLL_TARGET  = $(BUILD_DIR)/sii_decrypt.dll
EXE_TARGET  = $(BUILD_DIR)/sii_decrypt.exe

# --- Phony targets -------------------------------------------------------

.PHONY: all dll console clean

all: dll console

# ============================================================================
#  Build targets
# ============================================================================

dll: $(DLL_TARGET)

console: $(EXE_TARGET)

# --- DLL ----------------------------------------------------------------

$(DLL_TARGET): $(CORE_OBJ) $(DLL_OBJ) $(DEF_FILE) | $(BUILD_DIR)
	$(CXX) $(DLL_OBJ) $(CORE_OBJ) -o $(DLL_TARGET) $(DLL_LDFLAGS) $(LDFLAGS) $(LDLIBS)

# --- Console EXE ---------------------------------------------------------

$(EXE_TARGET): $(CORE_OBJ) $(CONSOLE_OBJ) | $(BUILD_DIR)
	$(CXX) $(CONSOLE_OBJ) $(CORE_OBJ) -o $(EXE_TARGET) $(LDFLAGS) $(LDLIBS)

# --- Object files --------------------------------------------------------

$(CORE_OBJ): $(CORE_SRC) $(SRC_DIR)/sii_core.h
	$(CXX) $(CXXFLAGS) -c $(CORE_SRC) -o $(CORE_OBJ)

$(DLL_OBJ): $(DLL_SRC) $(INC_DIR)/sii_decrypt.h $(SRC_DIR)/sii_core.h
	$(CXX) $(CXXFLAGS) -DSII_DECRYPT_DLL_EXPORTS -c $(DLL_SRC) -o $(DLL_OBJ)

$(CONSOLE_OBJ): $(CONSOLE_SRC) $(SRC_DIR)/sii_core.h
	$(CXX) $(CXXFLAGS) -c $(CONSOLE_SRC) -o $(CONSOLE_OBJ)

# --- Build directory -----------------------------------------------------

$(BUILD_DIR):
	@if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"

# ============================================================================
#  Clean
# ============================================================================

clean:
	@if exist "$(BUILD_DIR)\*.o"   del /q "$(BUILD_DIR)\*.o"
	@if exist "$(BUILD_DIR)\*.a"   del /q "$(BUILD_DIR)\*.a"
	@if exist "$(BUILD_DIR)\*.dll" del /q "$(BUILD_DIR)\*.dll"
	@if exist "$(BUILD_DIR)\*.exe" del /q "$(BUILD_DIR)\*.exe"
	@echo Clean complete.
