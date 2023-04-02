# VPN Fingerprinting C implementation

## Background

This directory contains the implementation of the research in C. The usage of C
language help to reduce 3rd party dependencies, and required less RAM, ROM and
CPU from the target device in compare to the Python implementation.

The main files of the implementations are:

### `new_packet_arrival.c`

This is the entry point of the program, at this file the kernel module creates
a `netfilter` hook, the summary of the settings can be seen in the following
snippet:

```c
struct nf_hook_ops nfho;
nfho.hook = hook_funcion;
nfho.hooknum = NF_INET_PRE_ROUTING;
nfho.pf = NFPROTO_IPV4;
nfho.priority = NF_IP_PRI_LAST;
nf_register_net_hook(&init_net, &nfho);
```

The hook function verify that the packet is an IPv4 packet and not an internal
communication, and if so transfer the source and destination IP addresses and
the router clock in seconds (`ktime_get_boottime_seconds()`) to the `analyze()`
function.

### `analyze_packet.c`

The file contains the logic of the VPN connections fingerprinting, a simplify
version can be found at the Python implementation or at the published paper.

The header file `analyze_packet.h` contains the 3 metric parameters that can be
tuned:

* `METRIC_COUNT_PACKETS`
* `METRIC_TIME_WINDOW_SEC`
* `METRIC_WINDOW_OVERLAP_THRESHOLD`

More info on this variables can be found at the published paper.

## Download the target SDK

Download the SDK that match the target device, in our case, we were using
NETGEAR AC1200 (R6120) and OpenWrt version 22.03.0, so the SDK was downloaded
from https://downloads.openwrt.org/releases/22.03.0/targets/ramips/mt76x8/

## Copy source files

The development files hierarchy is as follow:

```
.
└── openwrt-sdk-22.03.0-ramips-mt76x8_gcc-11.2.0_musl.Linux-x86_64
    ├── ...
    └── package
        ├── ...
        └── vpn_fingerprinting
            ├── Makefile
            └── src
                ├── analyze_packet.c
                ├── analyze_packet.h
                ├── Makefile
                └── new_packet_arrival.c
```

Note that there are two Makefiles, the repository file called `Makefile_2` is
the one at the `src` directory.

## First time configuration

At first time, the `.config` file should be generated using the command:

```
make menuconfig
```

Make sure that the module `kmod-vpn_fingerprinting` is marked with `M` at the
menu `Kernel modules` ---> `Other modules`, choose `Save` and then `Exit`.

## Create the `ipk` file

In order to create the `.ipk` file, run the following command from the SDK root
directory:

```
make package/vpn_fingerprinting/compile -j $(($(nproc)+1)) V=s
```

Note that both `-j` and `V` arguments are optional.

In our case, the generated file is created at:
`./openwrt-sdk-22.03.0-ramips-mt76x8_gcc-11.2.0_musl.Linux-x86_64/bin/targets/ramips/mt76x8/packages/`
the exact path is depends on the versions and target architecture.

## Copy the `ipk` file

The `ipk` file can be transferred to the router using `scp` command.

For example, to transfer a file called
`kmod-vpn_fingerprinting_5.10.138+1.04-ramips-1_mipsel_24kc.ipk` to the root
directory of a router at `192.168.1.1` using the username `root`, the following
command can be used:

```
scp kmod-vpn_fingerprinting_5.10.138+1.04-ramips-1_mipsel_24kc.ipk root@192.168.1.1:
```

## Install the package

OpenWrt is using `opkg` to install packages, use `opkg install <file>` to
install the generated package, for example:

```
opkg install kmod-vpn_fingerprinting_5.10.138+1.04-ramips-1_mipsel_24kc.ipk
```

## Inspect the output

The kernel module `vpn_fingerprinting.ko` prints his output to `dmesg` log.

## Kernel modules

The following commands can assist when dealing with kernel modules:

* `lsmod`: Show the status of Linux kernel modules.
* `modinfo`: Show information about a Linux kernel module.
* `insmod`: Insert a module into the Linux kernel.
* `rmmod`: Remove a module from the Linux kernel.

E.g. to remove the VPN fingerprinting module, run the following command:

```
rmmod vpn_fingerprinting.ko
```
