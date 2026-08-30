################################################################################
#
# python-ray
#
# Downloads Ray, scipy, numpy and all transitive dependencies as pre-built
# wheels at Buildroot build time and installs them into the target rootfs so
# the CVM does not need network access or pip at boot.
#
################################################################################

PYTHON_RAY_VERSION = 2.55.1
PYTHON_RAY_LICENSE = Apache-2.0
PYTHON_RAY_SOURCE =

PYTHON_RAY_SITE_PACKAGES = $(TARGET_DIR)/usr/lib/python3.14/site-packages

# The system python3 has ssl (via libssl) but not pip.
# The Buildroot host-python3 has pip (via venv) but was built without ssl.
# Work around both: bootstrap pip into a temp dir using the system python3's
# urllib (which does have ssl), then use that local pip to download wheels.
define PYTHON_RAY_BUILD_CMDS
	mkdir -p $(@D)/wheels $(@D)/pip-bootstrap
	python3 -c "import urllib.request; urllib.request.urlretrieve( \
		'https://bootstrap.pypa.io/get-pip.py', \
		'$(@D)/pip-bootstrap/get-pip.py')"
	python3 $(@D)/pip-bootstrap/get-pip.py --target $(@D)/pip-bootstrap -q
	PYTHONPATH=$(@D)/pip-bootstrap \
	python3 -m pip download \
		--only-binary :all: \
		--python-version 3.14 \
		--implementation cp \
		--dest $(@D)/wheels \
		"ray==$(PYTHON_RAY_VERSION)" scipy numpy
endef

define PYTHON_RAY_INSTALL_TARGET_CMDS
	mkdir -p $(PYTHON_RAY_SITE_PACKAGES)
	for whl in $(@D)/wheels/*.whl; do \
		[ -f "$$whl" ] || continue; \
		unzip -q -o "$$whl" -d $(PYTHON_RAY_SITE_PACKAGES)/; \
	done
	rm -rf $(PYTHON_RAY_SITE_PACKAGES)/*.data
	python3 $(BR2_EXTERNAL_FORT_PATH)/package/python-ray/gen-entrypoints.py \
		$(PYTHON_RAY_SITE_PACKAGES) $(TARGET_DIR)/usr/bin
endef

$(eval $(generic-package))
