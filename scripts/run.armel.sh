#!/bin/bash

set -e
set -u

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

if check_number $1; then
    echo "Usage: run.armel.sh <image ID>"
    exit 1
fi
IID=${1}
QEMU_INIT=${2}

WORK_DIR=`get_scratch ${IID}`
# sockets live in a private directory of this image (was predictable /tmp names)
mkdir -p -m 0700 "${WORK_DIR}/run"
rm -f "${WORK_DIR}"/run/*.sock
# one loopback port range per image for the unused placeholder NICs
SOCK_BASE=$((20000 + (IID % 10000) * 4))
IMAGE=`get_fs ${IID}`
KERNEL=`get_kernel "armel" false`
QEMU_MACHINE=`get_qemu_machine "armel"`
QEMU_ROOTFS=`get_qemu_disk "armel"`

if (${FIRMAE_NET}); then
  QEMU_NETWORK="-device virtio-net-device,netdev=net0 -netdev user,id=net0,restrict=on"
else
  QEMU_NETWORK="-device virtio-net-device,netdev=net0 -netdev socket,id=net0,listen=127.0.0.1:$((SOCK_BASE + 0)) -device virtio-net-device,netdev=net1 -netdev socket,id=net1,listen=127.0.0.1:$((SOCK_BASE + 1)) -device virtio-net-device,netdev=net2 -netdev socket,id=net2,listen=127.0.0.1:$((SOCK_BASE + 2)) -device virtio-net-device,netdev=net3 -netdev socket,id=net3,listen=127.0.0.1:$((SOCK_BASE + 3))"
fi

QEMU_AUDIO_DRV=none qemu-system-arm -m 256 -M ${QEMU_MACHINE} -kernel ${KERNEL} -drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs -append "firmadyne.syscall=1 root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${QEMU_INIT} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=${FIRMAE_NET} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} user_debug=31" -serial file:${WORK_DIR}/qemu.initial.serial.log -serial unix:${WORK_DIR}/run/serial1.sock,server,nowait -monitor unix:${WORK_DIR}/run/monitor.sock,server,nowait -display none ${QEMU_NETWORK}
