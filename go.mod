module github.com/florianl/go-nflog/v2

require (
	github.com/google/go-cmp v0.5.8
	github.com/mdlayher/netlink v1.6.0
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a
)

replace github.com/mdlayher/netlink => github.com/cloudlinux/netlink v1.6.1-0.20220802115504-7e652dd2c261

go 1.13
