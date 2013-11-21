include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-censorscope-tmpfs
PKG_VERSION:=v0.0.6-alpha
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/censorscope.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

include $(INCLUDE_DIR)/package.mk

MAKE_FLAGS += LUA_CFLAGS=""
MAKE_FLAGS += LUA_LIBS="-lm -lcrypt -llua"
MAKE_FLAGS += DEFAULT_SANDBOX_DIR="/var/censorscope/sandbox"
MAKE_FLAGS += DEFAULT_LUASRC_DIR="/tmp/usr/lib/lua/censorscope"
MAKE_FLAGS += DEFAULT_RESULTS_DIR="/var/censorscope/results"
MAKE_FLAGS += DEFAULT_MAX_MEMORY=1048576
MAKE_FLAGS += DEFAULT_MAX_INSTRUCTIONS=1048576
MAKE_FLAGS += DEFAULT_UPLOAD_TRANSPORT="bismark"

define Package/bismark-censorscope-tmpfs
	SECTION:=util
	CATEGORY:=Utilities
	TITLE:=Sandboxed Lua environment for running network experiments
	URL:=https://github.com/projectbismark/censorscope
	DEPENDS:=+bismark-data-transmit +liblua +libldns +libevent2 +libcurl
endef

define Package/bismark-censorscope-tmpfs/description
	Censorscope is a sandboxed Lua environment for running networking
	experiments, particularly experiments for measuring network filtering
	and censorship.
endef

define Package/bismark-censorscope-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/censorscope $(1)/usr/bin/censorscope
	$(INSTALL_DIR) $(1)/usr/lib/lua/censorscope
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/luasrc/api.lua $(1)/usr/lib/lua/censorscope/api.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/luasrc/utils.lua $(1)/usr/lib/lua/censorscope/utils.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/censorscope/transports
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/luasrc/transports/rsync.lua $(1)/usr/lib/lua/censorscope/transports/rsync.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/luasrc/transports/bismark.lua $(1)/usr/lib/lua/censorscope/transports/bismark.lua
	$(INSTALL_DIR) $(1)/censorscope/sandbox
	$(INSTALL_DIR) $(1)/censorscope/results
endef

$(eval $(call BuildPackage,bismark-censorscope-tmpfs))
