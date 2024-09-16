package org.torusresearch.torusutils.analytics;

import io.sentry.Sentry;

public class SentryUtils {

    public static void init() {
        Sentry.init(options -> {
            options.setDsn("https://bff95fa0489909b1f269f3bd099e3c6d@o503538.ingest.us.sentry.io/4507960706990080");
            options.setDebug(true);
        });
    }

    // Capture an exception
    public static void captureException(String msg) {
        Sentry.captureException(new Exception(msg));
    }

    public static void addBreadcrumb(String message) {
        Sentry.addBreadcrumb(message);
    }

    public static void logInformation(String clientId, String finalEvmAddress, String platform) {
        Sentry.configureScope(scope -> {
            scope.setTag("clientId", clientId);
            scope.setTag("finalEvmAddress", finalEvmAddress);
            scope.setTag("platform", platform);
        });
    }

    public static void setContext(String key, String value) {
        Sentry.configureScope(scope -> {
            scope.setExtra(key, value);
        });
    }

    public static void close() {
        Sentry.close();
    }
}

