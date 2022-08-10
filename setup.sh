#!/bin/bash

echo "Installing dependencies..."
sudo apt install gcc make

echo "Compiling executable..."
cd src
make -f makefile

echo "Making Systemwide Symlink..."
cd ..
sudo ln -sf $(pwd)/legolas /usr/local/bin/legolas

