# NaxDarks src_server/Makefile
# Builds Linux extender plugins and deploys to Server/extenders/.
# Usage:  make -C src_server SERVER_DIR=/path/to/adaptixserver/dist

NAX_ROOT    := $(shell cd .. && pwd)
SERVER_DIR  ?= $(NAX_ROOT)/../Server

AGENT_LINUX_DIR              := $(NAX_ROOT)/agent_naxdarks_linux
LISTENER_LINUX_TCP_DIR       := $(NAX_ROOT)/src_server/listener_naxdarks_linux_tcp
LISTENER_LINUX_HTTPS_DIR     := $(NAX_ROOT)/src_server/listener_naxdarks_linux_https
LISTENER_LINUX_GRAPH_DIR     := $(NAX_ROOT)/src_server/listener_naxdarks_linux_graph

DEPLOY_AGENT_LINUX            := $(SERVER_DIR)/extenders/agent_naxdarks_linux
DEPLOY_LISTENER_LINUX_TCP     := $(SERVER_DIR)/extenders/listener_naxdarks_linux_tcp
DEPLOY_LISTENER_LINUX_HTTPS   := $(SERVER_DIR)/extenders/listener_naxdarks_linux_https
DEPLOY_LISTENER_LINUX_GRAPH   := $(SERVER_DIR)/extenders/listener_naxdarks_linux_graph

GO           ?= /usr/local/go/bin/go
GOEXPERIMENT ?=

.PHONY: all clean agent-linux listener-linux-tcp listener-linux-https listener-linux-graph

all: agent-linux listener-linux-tcp listener-linux-https listener-linux-graph

agent-linux:
	@echo "  BUILD  agent_naxdarks_linux.so"
	@mkdir -p $(DEPLOY_AGENT_LINUX)
	@cd $(AGENT_LINUX_DIR) && GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_AGENT_LINUX)/agent_naxdarks_linux.so .
	@cp $(AGENT_LINUX_DIR)/ax_config.axs $(DEPLOY_AGENT_LINUX)/ax_config.axs
	@cp $(AGENT_LINUX_DIR)/config.yaml   $(DEPLOY_AGENT_LINUX)/config.yaml
	@echo "  DEPLOY $(DEPLOY_AGENT_LINUX)/"

listener-linux-tcp:
	@echo "  BUILD  listener_naxdarks_linux_tcp.so"
	@mkdir -p $(DEPLOY_LISTENER_LINUX_TCP)
	@cd $(LISTENER_LINUX_TCP_DIR) && GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_LISTENER_LINUX_TCP)/listener_naxdarks_linux_tcp.so .
	@cp $(LISTENER_LINUX_TCP_DIR)/ax_config.axs $(DEPLOY_LISTENER_LINUX_TCP)/ax_config.axs
	@cp $(LISTENER_LINUX_TCP_DIR)/config.yaml   $(DEPLOY_LISTENER_LINUX_TCP)/config.yaml
	@echo "  DEPLOY $(DEPLOY_LISTENER_LINUX_TCP)/"

listener-linux-https:
	@echo "  BUILD  listener_naxdarks_linux_https.so"
	@mkdir -p $(DEPLOY_LISTENER_LINUX_HTTPS)
	@cd $(LISTENER_LINUX_HTTPS_DIR) && GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_LISTENER_LINUX_HTTPS)/listener_naxdarks_linux_https.so .
	@cp $(LISTENER_LINUX_HTTPS_DIR)/ax_config.axs $(DEPLOY_LISTENER_LINUX_HTTPS)/ax_config.axs
	@cp $(LISTENER_LINUX_HTTPS_DIR)/config.yaml   $(DEPLOY_LISTENER_LINUX_HTTPS)/config.yaml
	@echo "  DEPLOY $(DEPLOY_LISTENER_LINUX_HTTPS)/"

listener-linux-graph:
	@echo "  BUILD  listener_naxdarks_linux_graph.so"
	@mkdir -p $(DEPLOY_LISTENER_LINUX_GRAPH)
	@cd $(LISTENER_LINUX_GRAPH_DIR) && GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -buildmode=plugin \
		-o $(DEPLOY_LISTENER_LINUX_GRAPH)/listener_naxdarks_linux_graph.so .
	@cp $(LISTENER_LINUX_GRAPH_DIR)/ax_config.axs $(DEPLOY_LISTENER_LINUX_GRAPH)/ax_config.axs
	@cp $(LISTENER_LINUX_GRAPH_DIR)/config.yaml   $(DEPLOY_LISTENER_LINUX_GRAPH)/config.yaml
	@echo "  DEPLOY $(DEPLOY_LISTENER_LINUX_GRAPH)/"

clean:
	@rm -f $(DEPLOY_AGENT_LINUX)/agent_naxdarks_linux.so
	@rm -f $(DEPLOY_LISTENER_LINUX_TCP)/listener_naxdarks_linux_tcp.so
	@rm -f $(DEPLOY_LISTENER_LINUX_HTTPS)/listener_naxdarks_linux_https.so
	@rm -f $(DEPLOY_LISTENER_LINUX_GRAPH)/listener_naxdarks_linux_graph.so
	@echo "  CLEAN  done"
