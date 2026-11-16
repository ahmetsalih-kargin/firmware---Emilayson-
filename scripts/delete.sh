#!/bin/bash

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

if check_number $1; then
    echo "Usage: $0 <image ID>"
    echo "This script deletes a whole project"
    exit 1
fi
IID=${1}
WORK_DIR=`get_scratch ${IID}`
IMAGE=`get_fs ${IID}`
IMAGE_DIR=`get_fs_mount ${IID}`

# Every process of this image references "${SCRATCH_DIR}/<IID>/" (image path,
# run.sh, logs). scratch_pids (firmae.config) compares with this
# installation's full path: the old `pgrep -f "/scratch/<IID>/"` also matched
# the processes of another FirmAE copy on the host that uses the same IID.
echo "checking the process table for processes of image ${IID} ..."
PIDS=`scratch_pids ${IID}`
if [ -n "${PIDS}" ]; then
    echo "stopping processes: ${PIDS}"
    sudo kill ${PIDS} 2>/dev/null || true
    sleep 3
    PIDS=`scratch_pids ${IID}`
    if [ -n "${PIDS}" ]; then
        echo "killing processes: ${PIDS}"
        sudo kill -9 ${PIDS} 2>/dev/null || true
    fi
fi

# Unmount the image and detach exactly the loop devices backed by it (the old
# umount.sh picked "the newest /dev/mapper entry", i.e. possibly another image).
echo "In case the filesystem is mounted, umount it now ..."
if mountpoint -q "${IMAGE_DIR}"; then
    sudo umount "${IMAGE_DIR}"
fi
if [ -e "${IMAGE}" ]; then
    for LOOP in `losetup -j "${IMAGE}" | cut -d: -f1`; do
        echo "detaching ${LOOP}"
        sudo losetup -d "${LOOP}" || true
    done
fi

# TAP devices are named tap<IID>_<n>, VLANs tap<IID>_<n>.<vlan>; delete the
# VLANs first. (The old loop `for i in 0 .. 4` iterated over "0", "..", "4".)
echo "In case the network is configured, reconfigure it now ..."
IFACES=`ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E "^tap${IID}_[0-9]+(\.[0-9]+)?$" || true`
for IFACE in `echo "${IFACES}" | grep '\.' || true` `echo "${IFACES}" | grep -v '\.' || true`; do
    echo "deleting ${IFACE}"
    sudo ip link delete "${IFACE}" || true
done

# firewall rules that isolate the guest (see isolate_guest_network in firmae.config)
sudo bash -c 'source ./firmae.config && unisolate_guest_network "$1"' _ ${IID} || true

#Cleanup database:
echo "Remove the database entries ..."
psql -d firmware -U firmadyne -h $PSQL_IP -t -q -c "DELETE from image WHERE id=${IID};"

#Cleanup filesystem:
echo "Clean up the file system ..."
# (the old `[ -f "/tmp/qemu.${IID}*" ]` test never matched: the glob was quoted)
# (older versions kept the sockets there; they now live in scratch/<IID>/run/,
# which is removed with the rest of scratch/<IID> below)
sudo rm -f "/tmp/qemu.${IID}" "/tmp/qemu.${IID}.S1"

if [ -f ./images/${IID}.tar.gz ]; then
    sudo rm ./images/${IID}.tar.gz
fi

if [ -f ./images/${IID}.kernel ]; then
    sudo rm ./images/${IID}.kernel
fi

if [ -d ./scratch/${IID}/ ]; then
    sudo rm -r ./scratch/${IID}/
fi

echo "Done. Removed project ID ${IID}."
