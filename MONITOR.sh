#!/bin/bash

cd esp32_k210_fw

source ../esp-idf/export.sh

idf.py monitor
