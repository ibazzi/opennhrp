#
# Copyright (C) 2009-2015 OpenWrt.org
# Copyright (C) 2009 Jakob Pfeiffer
# Copyright (C) 2014 Artem Makhutov
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=opennhrp
PKG_VERSION:=0.15
PKG_RELEASE:=1
PKG_MAINTAINER:=Artem Makhutov <artem@makhutov.org>
PKG_LICENSE:=MIT License

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/ibazzi/opennhrp.git
PKG_SOURCE_VERSION:=89be44f8afe67f4a0891edea155f66d001dde3c5

PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/opennhrp
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  DEPENDS:=+libcares +ip +kmod-gre
  KCONFIG:=CONFIG_ARPD=y
  TITLE:=NBMA Next Hop Resolution Protocol
  URL:=http://opennhrp.sourceforge.net/
endef

define Package/opennhrp/description
  OpenNHRP implements NBMA Next Hop Resolution Protocol (as defined in RFC 2332).
  It makes it possible to create dynamic multipoint VPN Linux router using NHRP,
  GRE and IPsec. It aims to be Cisco DMVPN compatible.
endef

define Package/opennhrp/conffiles
/etc/opennhrp/opennhrp.conf
endef

define Package/opennhrp/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/opennhrp{,ctl} $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/opennhrp
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/opennhrp/opennhrp.conf $(1)/etc/opennhrp/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/etc/opennhrp/opennhrp-script $(1)/etc/opennhrp/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/opennhrp.init $(1)/etc/init.d/opennhrp
endef

$(eval $(call BuildPackage,opennhrp))
