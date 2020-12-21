#!/bin/bash

cd esp32_k210_fw

source ../esp-idf/export.sh

idf.py flash -p /dev/ttyUSB0 monitor
