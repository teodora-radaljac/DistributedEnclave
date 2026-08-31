################################################################################
#
# Fort Client
#
################################################################################

FORT_CLIENT_VERSION = main
FORT_CLIENT_SITE = $(BR2_EXTERNAL_FORT_PATH)/../../fort
FORT_CLIENT_SITE_METHOD = local
FORT_CLIENT_GOMOD = github.com/danko-miladinovic/fort/client
FORT_CLIENT_SUBDIR = client
FORT_CLIENT_BIN_NAME = client

# The local site method bypasses the go-post-process download step that
# normally runs go mod vendor. Run it explicitly after every rsync so
# the build directory has a complete vendor tree before the Go build.
define FORT_CLIENT_VENDOR_DEPS
	cd $(@D)/$(FORT_CLIENT_SUBDIR); \
	GO111MODULE=on \
	GOFLAGS= \
	GOROOT="$(HOST_GO_ROOT)" \
	GOPATH="$(HOST_GO_GOPATH)" \
	GOCACHE="$(HOST_GO_TARGET_CACHE)" \
	GOMODCACHE="$(HOST_GO_GOPATH)/pkg/mod" \
	GOPROXY=direct \
	GOTOOLCHAIN=local \
	PATH=$(BR_PATH) \
	$(GO_BIN) mod vendor -modcacherw
endef
FORT_CLIENT_POST_RSYNC_HOOKS += FORT_CLIENT_VENDOR_DEPS

define FORT_CLIENT_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/bin/client $(TARGET_DIR)/usr/bin/client
	$(INSTALL) -D -m 0644 $(BR2_EXTERNAL_FORT_PATH)/package/fort-client/fort-client.service \
		$(TARGET_DIR)/usr/lib/systemd/system/fort-client.service
	mkdir -p $(TARGET_DIR)/etc/systemd/system/multi-user.target.wants
	ln -sf /usr/lib/systemd/system/fort-client.service \
		$(TARGET_DIR)/etc/systemd/system/multi-user.target.wants/fort-client.service
endef

$(eval $(golang-package))
