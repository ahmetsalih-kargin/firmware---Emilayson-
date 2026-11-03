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

# Every process of this image references ".../scratch/<IID>/" (image path,
# run.sh, logs) -- on the host and, in Docker mode, as /work/FirmAE/scratch/...
# Matching "/scratch/<IID>/" -- not just the number -- keeps IID 1 from
# matching IID 10, 11, 21, ... (the old `grep "${IID}"` did).
PATTERN="/scratch/${IID}/"
echo "checking the process table for processes of image ${IID} ..."
PIDS=`pgrep -f -- "${PATTERN}" || true`
if [ -n "${PIDS}" ]; then
    echo "stopping processes: ${PIDS}"
    sudo kill ${PIDS} 2>/dev/null || true
    sleep 3
    PIDS=`pgrep -f -- "${PATTERN}" || true`
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

#Cleanup database:
echo "Remove the database entries ..."
psql -d firmware -U firmadyne -h $PSQL_IP -t -q -c "DELETE from image WHERE id=${IID};"

#Cleanup filesystem:
echo "Clean up the file system ..."
# (the old `[ -f "/tmp/qemu.${IID}*" ]` test never matched: the glob was quoted)
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
