#!/bin/bash

read install_path < ~/.honeygrove_install

cd "$install_path"
cd ..
python3 -m honeygrove "$@"
