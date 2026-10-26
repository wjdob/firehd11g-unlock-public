#!/system/bin/sh
# Mirror the host-side 10ms wait patch (docs/ENODATA-ANALYSIS.md) onto both
# staged carrier copies, in place (preserves inode/owner/SELinux label).
# 0x11c8 = 4552 decimal; new tv_nsec = 10000000 = 0x989680 (LE: 80 96 98 00 00 00 00 00)
SN=/data/user/0/com.amazon.webview.chromium/files/sn
for f in "$SN/libhwbinder_target.so" "$SN/libhwbinder_target.arm64-v8a.so"; do
  printf '\200\226\230\0\0\0\0\0' | toybox dd of="$f" bs=1 seek=4552 conv=notrunc 2>/dev/null
done
toybox sha256sum "$SN/libhwbinder_target.so" "$SN/libhwbinder_target.arm64-v8a.so"
toybox od -An -tx1 -j 4552 -N 8 "$SN/libhwbinder_target.arm64-v8a.so"
