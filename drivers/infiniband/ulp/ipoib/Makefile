obj-$(CONFIG_INFINIBAND_IPOIB)			+= ib_ipoib.o

ib_ipoib-y					:= ipoib_main.o \
						   ipoib_ib.o \
						   ipoib_multicast.o \
						   ipoib_verbs.o \
						   ipoib_vlan.o \
						   ipoib_ethtool.o \
						   ipoib_ioctl.o \
						   ipoib_acl.o \
						   ipoib_netlink.o
ib_ipoib-$(CONFIG_INFINIBAND_IPOIB_CM)		+= ipoib_cm.o
ib_ipoib-$(CONFIG_INFINIBAND_IPOIB_DEBUG)	+= ipoib_fs.o

