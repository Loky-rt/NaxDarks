extenders:
  - name: listener_naxdarks_linux_https
    version: 0.1.0
    type: listener
    description: "NaxDarks HTTPS listener"
    author: DarksBlack
    min_server_version: "v2.0"
    source: src_server/listener_naxdarks_linux_https
    build:
      - go build -buildmode=plugin -o listener_naxdarks_linux_https.so .
    release:
      globs:
        - "*.so"
        - "ax_config.axs"
        - "config.yaml"

  - name: listener_naxdarks_linux_tcp
    version: 0.1.0
    type: listener
    description: "NaxDarks TCP listener"
    author: DarksBlack
    min_server_version: "v2.0"
    source: src_server/listener_naxdarks_linux_tcp
    build:
      - go build -buildmode=plugin -o listener_naxdarks_linux_tcp.so .
    release:
      globs:
        - "*.so"
        - "ax_config.axs"
        - "config.yaml"

  - name: agent_naxdarks_linux
    version: 0.1.0
    type: agent
    description: "Agent plugin"
    author: DarksBlack
    min_server_version: "v2.0"
    source: agent_naxdarks_linux
    deps:
      apt:
        - gcc
        - gcc-aarch64-linux-gnu
        - libssl-dev
        - zlib1g-dev
        - python3
        - make
    build:
      - 'find /home /opt /srv /mnt /tmp -type d -name NaxDarks* ! -path "*/AdaptixC2/*" -printf "%T@ %p\n" 2>/dev/null | sort -nr | head -n 1 | cut -d" " -f2- > nax_root.conf'
      - go build -buildmode=plugin -o agent_naxdarks_linux.so .
    release:
      globs:
        - "*.so"
        - "ax_config.axs"
        - "config.yaml"
        - "nax_root.conf"
