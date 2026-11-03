#!/bin/bash
# Remove what FirmAE leaves behind -- and nothing else.
# The old version removed EVERY container on the host (`docker ps -a | xargs
# docker rm -f`) and detached EVERY loop device (`losetup -D`).

# containers started from the FirmAE core image (docker-helper.py runs "fcore")
docker ps -aq --filter ancestor=fcore | xargs -r docker rm -f

# mounts and loop devices of FirmAE images (scratch/<IID>/image.raw), on the
# host or created inside a container (/work/FirmAE/scratch/...)
findmnt -rn -o TARGET | grep -E '/scratch/[0-9]+/image$' | sort -r | while read -r MNT; do
    sudo umount "${MNT}"
done
losetup -l -n -O NAME,BACK-FILE | awk '$2 ~ /\/scratch\/[0-9]+\/image\.raw$/ {print $1}' |
while read -r LOOP; do
    sudo losetup -d "${LOOP}"
done
