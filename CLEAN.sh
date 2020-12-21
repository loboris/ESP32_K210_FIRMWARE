#!/bin/bash

cd esp32_k210_fw

rm -R -v build/*

source ../esp-idf/export.sh

idf.py clean
