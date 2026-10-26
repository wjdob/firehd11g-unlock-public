#!/system/bin/sh
set -eu

# PS7319: assets live in the webview app's own files dir (staged by the
# uid-10161 channel). See PS7319-ADAPTATION.md.
asset_dir=/data/user/0/com.amazon.webview.chromium/files/sn
app_process=/system/bin/app_process64
main_class=com.android.webview.chromium.WebViewChromiumFactoryProviderForP

if [ ! -x "$app_process" ]; then
    echo "SNU_ABI_ERROR: app_process64 is unavailable" >&2
    exit 70
fi
export CLASSPATH="$asset_dir/agent.jar"
exec "$app_process" /system/bin "$main_class"