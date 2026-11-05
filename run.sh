#!/bin/bash
# FirmAE entry point. The pipeline lives in the Python package firmae/
# (firmae/pipeline.py); this wrapper keeps the old command line:
#
#   sudo ./run.sh [-r|-c|-a|-d|-b] <brand> <firmware|firmware_directory>
#
# Exit status: 0 = success; otherwise the code of the stage that failed
# (see firmae/errors.py). Before, the exit status was 0 whatever happened.
export FIRMAE_PROG="${0}"
export PYTHONPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)${PYTHONPATH:+:${PYTHONPATH}}"
exec python3 -m firmae "$@"
