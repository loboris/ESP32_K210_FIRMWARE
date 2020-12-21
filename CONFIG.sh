#!/bin/bash

cd esp32_k210_fw

rm -R -f build/*

source ../esp-idf/export.sh

idf.py menuconfig
