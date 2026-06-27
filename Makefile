# ============================================================================
#  SII Decrypt - Makefile (GCC/MinGW-w64, Windows cmd)
#
#  Zero external dependencies — AES-256 + DEFLATE are self-contained.
#
#  Targets:
#    mingw32-make all       — build DLL + console program
#    mingw32-make dll       — build sii_decrypt.dll only
#    mingw32-make console   — build sii_decrypt.exe only
#    mingw32-make clean     — remove build artifacts
# ============================================================================

SHELL = cmd.exe

# --- Toolchain -----------------------------------------------------------

CXX      = g++

# --- Paths ---------------------------------------------------------------

INC_DIR  = include
SRC_DIR  = src
BLD_DIR  = build

# --- Compiler flags ------------------------------------------------------

CXXFLAGS  = -std=c++11 -Wall -Wextra -O2 -fvisibility=hidden
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -I$(SRC_DIR) -I$(SRC_DIR)/core -I$(SRC_DIR)/crypto -I$(SRC_DIR)/compress

# --- Linker flags --------------------------------------------------------

LDFLAGS   = -static
LDLIBS    =

# DLL flags
DEF_FILE  = $(SRC_DIR)/sii_decrypt.def
DLL_FLAGS = -shared -static-libgcc -static-libstdc++ \
            -Wl,$(DEF_FILE) \
            -Wl,--out-implib,$(BLD_DIR)/libsii_decrypt.a

# --- Source files --------------------------------------------------------

AES_SRC      = $(SRC_DIR)/crypto/aes256.cpp
INFLATE_SRC  = $(SRC_DIR)/compress/inflate.cpp
FORMAT_SRC   = $(SRC_DIR)/core/sii_format.cpp
DECRYPTOR_SRC= $(SRC_DIR)/core/sii_decryptor.cpp
DLL_SRC      = $(SRC_DIR)/sii_dll.cpp
CONSOLE_SRC  = $(SRC_DIR)/sii_console.cpp

# --- Object files --------------------------------------------------------

AES_OBJ      = $(BLD_DIR)/aes256.o
INFLATE_OBJ  = $(BLD_DIR)/inflate.o
FORMAT_OBJ   = $(BLD_DIR)/sii_format.o
DECRYPTOR_OBJ= $(BLD_DIR)/sii_decryptor.o
DLL_OBJ      = $(BLD_DIR)/sii_dll.o
CONSOLE_OBJ  = $(BLD_DIR)/sii_console.o

# --- Output targets ------------------------------------------------------

DLL_TARGET   = $(BLD_DIR)/sii_decrypt.dll
EXE_TARGET   = $(BLD_DIR)/sii_decrypt.exe

# --- Phony targets -------------------------------------------------------

.PHONY: all dll console clean

all: dll console

dll:     $(DLL_TARGET)
console: $(EXE_TARGET)

# Objects linked into every binary
COMMON = $(AES_OBJ) $(INFLATE_OBJ) $(FORMAT_OBJ) $(DECRYPTOR_OBJ)

# --- DLL ----------------------------------------------------------------

$(DLL_TARGET): $(COMMON) $(DLL_OBJ) $(DEF_FILE) | $(BLD_DIR)
	$(CXX) $(DLL_OBJ) $(COMMON) -o $@ $(DLL_FLAGS) $(LDFLAGS) $(LDLIBS)

# --- Console EXE ---------------------------------------------------------

$(EXE_TARGET): $(COMMON) $(CONSOLE_OBJ) | $(BLD_DIR)
	$(CXX) $(CONSOLE_OBJ) $(COMMON) -o $@ $(LDFLAGS) $(LDLIBS)

# --- Object rules --------------------------------------------------------

$(AES_OBJ): $(AES_SRC) $(SRC_DIR)/crypto/aes256.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(INFLATE_OBJ): $(INFLATE_SRC) $(SRC_DIR)/compress/inflate.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(FORMAT_OBJ): $(FORMAT_SRC) $(SRC_DIR)/core/sii_types.h $(SRC_DIR)/core/sii_format.h \
               $(SRC_DIR)/crypto/aes256.h $(SRC_DIR)/compress/inflate.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(DECRYPTOR_OBJ): $(DECRYPTOR_SRC) $(SRC_DIR)/core/sii_types.h $(SRC_DIR)/core/sii_decryptor.h \
                  $(SRC_DIR)/core/sii_format.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(DLL_OBJ): $(DLL_SRC) $(INC_DIR)/sii_decrypt.h $(SRC_DIR)/core/sii_decryptor.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -DSII_DECRYPT_DLL_EXPORTS -c $< -o $@

$(CONSOLE_OBJ): $(CONSOLE_SRC) $(SRC_DIR)/core/sii_types.h $(SRC_DIR)/core/sii_format.h \
                $(SRC_DIR)/crypto/aes256.h $(SRC_DIR)/compress/inflate.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- Build directory -----------------------------------------------------

$(BLD_DIR):
	@if not exist "$(BLD_DIR)" mkdir "$(BLD_DIR)"

# --- Clean ---------------------------------------------------------------

clean:
	@if exist "$(BLD_DIR)\*.o"   del /q "$(BLD_DIR)\*.o"
	@if exist "$(BLD_DIR)\*.a"   del /q "$(BLD_DIR)\*.a"
	@if exist "$(BLD_DIR)\*.dll" del /q "$(BLD_DIR)\*.dll"
	@if exist "$(BLD_DIR)\*.exe" del /q "$(BLD_DIR)\*.exe"
	@echo Clean complete.
