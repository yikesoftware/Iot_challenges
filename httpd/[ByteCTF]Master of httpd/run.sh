#!/bin/sh
sudo chroot ./ ./qemu-aarch64-static -L /lib ./mini_httpd -C ./mini_httpd.conf -D
