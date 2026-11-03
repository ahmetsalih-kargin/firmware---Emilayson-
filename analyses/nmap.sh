#!/bin/bash

set -u

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: $0 <image ID> [target IP]"
    exit 1
fi

IID=${1}
if check_number "${IID}"; then
    echo "[-] invalid image ID: ${IID}"
    exit 1
fi
WORK_DIR=`get_scratch ${IID}`
LOG_DIR="${WORK_DIR}/analysis_log"

#Nmap options to use for scanning:
NMAP_OPTS="-v -n -sSV"

if ! which nmap > /dev/null; then
    echo "[-] missing nmap binary"
    exit 1
fi

if ! [ -d ${WORK_DIR} ]; then
    echo "[-] missing working directory of image ID ${IID}"
    exit 1
fi

# The generated run.sh never contained a "GUESTIP=" line, so the old lookup
# always failed. Use the target analyses_all.sh passes to every tool, or the
# address check_emulation.sh recorded.
if [ $# -eq 2 ]; then
    TARGET_IP=${2}
elif [ -f "${WORK_DIR}/ip" ]; then
    TARGET_IP=`cat "${WORK_DIR}/ip"`
else
    TARGET_IP=""
fi

if [ -z "${TARGET_IP}" ]; then
    echo "[-] Found no target IP address ..."
    exit 1
fi

echo "[+] Found IP: ${TARGET_IP}"

mkdir -p "${LOG_DIR}"
sudo nmap ${NMAP_OPTS} "${TARGET_IP}" -oA "${WORK_DIR}/nmap-basic-tcp" | tee "${WORK_DIR}/nmap-basic-tcp.txt" 2>&1

# fuzzer.py reads the XML report from analysis_log/nmap_log.txt
if [ -f "${WORK_DIR}/nmap-basic-tcp.xml" ]; then
    cp "${WORK_DIR}/nmap-basic-tcp.xml" "${LOG_DIR}/nmap_log.txt"
else
    echo "[-] nmap produced no XML report"
    exit 1
fi

echo -e "\nDumped Nmap scan details of ${TARGET_IP} to ${WORK_DIR}"


