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
    echo "Usage: run.mipseb.sh <image ID>"
    exit 1
fi
IID=${1}
QEMU_INIT=${2}

WORK_DIR=`get_scratch ${IID}`
# sockets live in a private directory of this image (was predictable /tmp names)
mkdir -p "${WORK_DIR}/run"
chmod 0700 "${WORK_DIR}/run"
rm -f "${WORK_DIR}"/run/*.sock
# one loopback port range per image for the unused placeholder NICs
SOCK_BASE=$((20000 + (IID % 10000) * 4))
IMAGE=`get_fs ${IID}`
KERNEL=`get_kernel "mipseb" false`
QEMU_MACHINE=`get_qemu_machine "mipseb"`
QEMU_ROOTFS=`get_qemu_disk "mipseb"`

if (${FIRMAE_NET}); then
  QEMU_NETWORK="-device e1000,netdev=net1 -netdev user,id=net1,restrict=on -device e1000,netdev=net2 -netdev user,id=net2,restrict=on -device e1000,netdev=net3 -netdev user,id=net3,restrict=on -device e1000,netdev=net4 -netdev user,id=net4,restrict=on"
else
  QEMU_NETWORK="-device e1000,netdev=net0 -netdev socket,id=net0,listen=127.0.0.1:$((SOCK_BASE + 0)) -device e1000,netdev=net1 -netdev socket,id=net1,listen=127.0.0.1:$((SOCK_BASE + 1)) -device e1000,netdev=net2 -netdev socket,id=net2,listen=127.0.0.1:$((SOCK_BASE + 2)) -device e1000,netdev=net3 -netdev socket,id=net3,listen=127.0.0.1:$((SOCK_BASE + 3))"
fi

qemu-system-mips -m 256 -M ${QEMU_MACHINE} -kernel ${KERNEL} -drive if=ide,format=raw,file=${IMAGE} -append "firmadyne.syscall=1 root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${QEMU_INIT} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=${FIRMAE_NET} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} user_debug=31" -serial file:${WORK_DIR}/qemu.initial.serial.log -serial unix:${WORK_DIR}/run/serial1.sock,server,nowait -monitor unix:${WORK_DIR}/run/monitor.sock,server,nowait -display none ${QEMU_NETWORK}
