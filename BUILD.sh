#!/bin/bash

cd esp32_k210_fw

source ../esp-idf/export.sh

idf.py build

if [ $? -eq 0 ]; then
    echo ""
    # echo "==== SIZES ===="
    # idf_size.py --archives build/mkm2019.map
fi

