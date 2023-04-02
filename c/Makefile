################################################################################
# OpenWrt Makefile for the home router VPN
# fingerprinting program
#
#
# Most of the variables used here are defined in the include directives below.
# We just need to specify a basic description of the package, where to build our
# program, where to find the source files, and where to install the compiled
# program on the router.
#
################################################################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=vpn-fingerprinting
PKG_VERSION:=1.05
PKG_RELEASE:=1
PKG_LICENSE:=GPL

# This specifies the directory where we're going to build the program.
# The root build directory, $(BUILD_DIR), is by default the build_mipsel
# directory in your OpenWrt SDK directory
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
SOURCE_DIR:=./src

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

# Specify package information for this program.
define KernelPackage/vpn_fingerprinting
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Other modules
  TITLE:=VPN Fingerprinting On Home Router
  #URL:=
  VERSION:=$(LINUX_VERSION)+$(PKG_VERSION)-$(BOARD)-$(PKG_RELEASE)
  FILES:=$(PKG_BUILD_DIR)/vpn_fingerprinting.ko
  AUTOLOAD:=$(call AutoLoad,30,vpn_fingerprinting)
endef

define KernelPackage/vpn_fingerprinting/description
 VPN Fingerprinting On Home Router
 By Sultan Almutairi, Yogev Neumann and Khaled Harfoush,
 North Carolina State University.
endef

# Specify what needs to be done to prepare for building the package.
# In our case, we need to copy the source files to the build directory.
# This is NOT the default. The default uses the PKG_SOURCE_URL and the
# PKG_SOURCE which is not defined here to download the source from the web.
# In order to just build a simple program that we have just written, it is much
# easier to do it this way.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
	$(Build/Patch)
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		$(KERNEL_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)" \
		modules
endef

# This line executes the necessary commands to compile our program.
# The above define directives specify all the information needed, but this line
# calls BuildPackage which in turn actually uses this information to build a
# package.
$(eval $(call KernelPackage,vpn_fingerprinting))
