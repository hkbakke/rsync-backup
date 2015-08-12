#!/bin/bash

rootdir=$(dirname "${BASH_SOURCE[0]}")
confdir="${rootdir}/conf.d"
max_concurrent=2

find "$confdir" -name "*.conf" -exec basename '{}' .conf \; \
    | xargs --max-args=1 --max-procs=$max_concurrent \
    python3 "${rootdir}/backup.py" -q -c
