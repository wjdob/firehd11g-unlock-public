#!/system/bin/sh
# Read-only partition dump script for Fire HD 10 11th gen (trona/MT8183).
# Runs as uid 0 via the 127.0.0.1:4325 root listener. Writes only to
# /data/local/tmp/dumps. Never writes to any block device.
# NOTE: toybox dd rejects "1M" suffixes - use explicit byte counts.
D=/data/local/tmp/dumps
mkdir -p $D

# name:blocksize:count  (block sizes in bytes, counts from /proc/partitions KB)
dump() {
  dd if=/dev/block/$1 of=$D/$1.bin bs=$2 count=$3 2>/dev/null
  echo "dumped $1 ($(($2 * $3)) bytes)"
}

# Small boot-critical partitions
dump mmcblk0p1 512 2048        # kb        1 MiB
dump mmcblk0p2 512 2048        # dkb       1 MiB
dump mmcblk0p3 512 16384       # keys      8 MiB
dump mmcblk0p4 512 2048        # misc      1 MiB
dump mmcblk0p5 512 2048        # lk        1 MiB
dump mmcblk0p6 512 10240       # tee1      5 MiB
dump mmcblk0p7 512 10240       # tee2      5 MiB
dump mmcblk0p9 512 2048        # boot_para 1 MiB
dump mmcblk0p10 512 16384      # nvcfg    16 MiB
dump mmcblk0p11 512 2048       # spmfw     1 MiB
dump mmcblk0p12 512 2048       # sspm_1    1 MiB

# eMMC hardware boot partitions (MTK preloader candidates)
dump mmcblk0boot0 512 8192     # 4 MiB
dump mmcblk0boot1 512 8192     # 4 MiB

# RPMB (expected to fail without authenticated access; try 1 sector)
dd if=/dev/block/mmcblk0rpmb of=$D/mmcblk0rpmb.bin bs=512 count=1 2>/dev/null

ls -la $D
echo ---SHA256---
sha256sum $D/*
