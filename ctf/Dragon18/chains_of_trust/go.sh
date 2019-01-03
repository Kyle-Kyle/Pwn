#!/bin/bash
# Default Ubuntu 17.10 environment (if it doesn't work, get Ubuntu 17.10).
chmod a+x ./ld-linux-x86-64.so.2
chmod a+x ./chains
./ld-linux-x86-64.so.2 --library-path . ./chains

