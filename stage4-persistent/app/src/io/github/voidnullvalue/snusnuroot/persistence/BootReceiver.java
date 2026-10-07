package io.github.voidnullvalue.snusnuroot.persistence;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public final class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "SnuSnuPersist";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "receiver action=" + intent.getAction());
        try {
            context.startForegroundService(new Intent(context, PersistenceService.class));
        } catch (Throwable error) {
            Log.e(TAG, "startForegroundService failed", error);
        }
    }
}
