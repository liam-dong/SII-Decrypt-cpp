# ============================================================================
#  SII Decrypt
#
#  Zero external dependencies — AES-256 + DEFLATE are self-contained.
#
#  Targets:
#    make all       — build DLL + console program
#    make dll       — build sii_decrypt.dll only
#    make console   — build sii_decrypt.exe only
#    make clean     — remove build artifacts
# ============================================================================

SHELL = cmd.exe

# --- Toolchain -----------------------------------------------------------

CXX      = $(mingw32)\g++.exe

# --- Paths ---------------------------------------------------------------

INC_DIR  = include
SRC_DIR  = src
BLD_DIR  = build

# --- Compiler flags (max optimization, self-contained, 32-bit) -----------

CXXFLAGS  = -m32 -std=c++11 -Wall -Wextra -O3
CXXFLAGS += -fomit-frame-pointer -ffunction-sections -fdata-sections
CXXFLAGS += -I$(INC_DIR)
CXXFLAGS += -I$(SRC_DIR) -I$(SRC_DIR)/core -I$(SRC_DIR)/crypto -I$(SRC_DIR)/compress

# --- Common linker flags (fully static, stripped, LTO) -------------------

LD_COMMON = -static -static-libgcc -static-libstdc++ -s -Wl,--gc-sections

# --- DLL flags -----------------------------------------------------------

DEF_FILE  = $(SRC_DIR)/sii_decrypt.def
DLL_FLAGS = -shared \
            -Wl,$(DEF_FILE) \
            -Wl,--out-implib,$(BLD_DIR)/libsii_decrypt.a

# --- Source files --------------------------------------------------------

AES_SRC       = $(SRC_DIR)/crypto/aes256.cpp
INFLATE_SRC   = $(SRC_DIR)/compress/inflate.cpp
FORMAT_SRC    = $(SRC_DIR)/core/sii_format.cpp
BIN_UTILS_SRC = $(SRC_DIR)/core/sii_bin_utils.cpp
BIN_VALUE_SRC = $(SRC_DIR)/core/sii_bin_value.cpp
BIN_DATA_SRC  = $(SRC_DIR)/core/sii_bin_data.cpp
BIN_DEC_SRC   = $(SRC_DIR)/core/sii_bin_decoder.cpp
DECRYPTOR_SRC = $(SRC_DIR)/core/sii_decryptor.cpp
DLL_SRC       = $(SRC_DIR)/sii_dll.cpp
CONSOLE_SRC   = $(SRC_DIR)/sii_console.cpp

# --- Object files --------------------------------------------------------

AES_OBJ       = $(BLD_DIR)/aes256.o
INFLATE_OBJ   = $(BLD_DIR)/inflate.o
FORMAT_OBJ    = $(BLD_DIR)/sii_format.o
BIN_UTILS_OBJ = $(BLD_DIR)/sii_bin_utils.o
BIN_VALUE_OBJ = $(BLD_DIR)/sii_bin_value.o
BIN_DATA_OBJ  = $(BLD_DIR)/sii_bin_data.o
BIN_DEC_OBJ   = $(BLD_DIR)/sii_bin_decoder.o
DECRYPTOR_OBJ = $(BLD_DIR)/sii_decryptor.o
DLL_OBJ       = $(BLD_DIR)/sii_dll.o
CONSOLE_OBJ   = $(BLD_DIR)/sii_console.o

# --- Output targets ------------------------------------------------------

DLL_TARGET   = $(BLD_DIR)/sii_decrypt.dll
EXE_TARGET   = $(BLD_DIR)/sii_decrypt.exe

# --- Phony targets -------------------------------------------------------

.PHONY: all dll console clean

all: dll console

dll:     $(DLL_TARGET)
console: $(EXE_TARGET)

# Objects linked into every binary
COMMON = $(AES_OBJ) $(INFLATE_OBJ) $(FORMAT_OBJ) $(BIN_UTILS_OBJ) $(BIN_VALUE_OBJ) \
         $(BIN_DATA_OBJ) $(BIN_DEC_OBJ) $(DECRYPTOR_OBJ)

# --- DLL ----------------------------------------------------------------

$(DLL_TARGET): $(COMMON) $(DLL_OBJ) $(DEF_FILE) | $(BLD_DIR)
	$(CXX) $(DLL_OBJ) $(COMMON) -o $@ $(DLL_FLAGS) $(LD_COMMON)

# --- Console EXE ---------------------------------------------------------

$(EXE_TARGET): $(COMMON) $(CONSOLE_OBJ) | $(BLD_DIR)
	$(CXX) $(CONSOLE_OBJ) $(COMMON) -o $@ $(LD_COMMON)

# --- Object rules --------------------------------------------------------

$(AES_OBJ): $(AES_SRC) $(SRC_DIR)/crypto/aes256.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(INFLATE_OBJ): $(INFLATE_SRC) $(SRC_DIR)/compress/inflate.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(FORMAT_OBJ): $(FORMAT_SRC) $(SRC_DIR)/core/sii_types.h $(SRC_DIR)/core/sii_format.h \
               $(SRC_DIR)/crypto/aes256.h $(SRC_DIR)/compress/inflate.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN_UTILS_OBJ): $(BIN_UTILS_SRC) $(SRC_DIR)/core/sii_bin_types.h $(SRC_DIR)/core/sii_bin_utils.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN_VALUE_OBJ): $(BIN_VALUE_SRC) $(SRC_DIR)/core/sii_bin_types.h $(SRC_DIR)/core/sii_bin_utils.h \
                  $(SRC_DIR)/core/sii_bin_value.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN_DATA_OBJ): $(BIN_DATA_SRC) $(SRC_DIR)/core/sii_bin_types.h $(SRC_DIR)/core/sii_bin_utils.h \
                 $(SRC_DIR)/core/sii_bin_value.h $(SRC_DIR)/core/sii_bin_data.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN_DEC_OBJ): $(BIN_DEC_SRC) $(SRC_DIR)/core/sii_bin_types.h $(SRC_DIR)/core/sii_bin_utils.h \
                $(SRC_DIR)/core/sii_bin_data.h $(SRC_DIR)/core/sii_bin_decoder.h | $(BLD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(DECRYPTOR_OBJ): $(DECRYPTOR_SRC) $(SRC_DIR)/core/sii_types.h $(SRC_DIR)/core/sii_decryptor.h \
                  $(SRC_DIR)/core/sii_format.h $(SRC_DIR)/core/sii_bin_decoder.h | $(BLD_DIR)
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
