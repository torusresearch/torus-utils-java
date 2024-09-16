package org.torusresearch.torusutils.helpers;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.analytics.SentryUtils;

public class TorusUtilError extends Exception {

    // Define error cases
    public static final TorusUtilError CONFIGURATION_ERROR = new TorusUtilError("SDK Configuration incorrect. Network is probably incorrect", TorusUtils.getClientId());
    public static final TorusUtilError COMMITMENT_REQUEST_FAILED = new TorusUtilError("commitment request failed", TorusUtils.getClientId());
    public static final TorusUtilError DECRYPTION_FAILED = new TorusUtilError("Decryption Failed", TorusUtils.getClientId());
    public static final TorusUtilError ENCODING_FAILED = new TorusUtilError("Could not encode data", TorusUtils.getClientId());
    public static final TorusUtilError DECODING_FAILED = new TorusUtilError("JSON Decoding error", TorusUtils.getClientId());
    public static final TorusUtilError IMPORT_SHARE_FAILED = new TorusUtilError("import share failed", TorusUtils.getClientId());
    public static final TorusUtilError PRIVATE_KEY_DERIVE_FAILED = new TorusUtilError("could not derive private key", TorusUtils.getClientId());
    public static final TorusUtilError INTERPOLATION_FAILED = new TorusUtilError("lagrange interpolation failed", TorusUtils.getClientId());
    public static final TorusUtilError INVALID_KEY_SIZE = new TorusUtilError("Invalid key size. Expected 32 bytes", TorusUtils.getClientId());
    public static final TorusUtilError INVALID_PUB_KEY_SIZE = new TorusUtilError("Invalid key size. Expected 64 bytes", TorusUtils.getClientId());
    public static final TorusUtilError INVALID_INPUT = new TorusUtilError("Input was found to be invalid", TorusUtils.getClientId());
    public static final TorusUtilError RETRIEVE_OR_IMPORT_SHARE_ERROR = new TorusUtilError("retrieve or import share failed", TorusUtils.getClientId());
    public static final TorusUtilError METADATA_NONCE_MISSING = new TorusUtilError("Unable to fetch metadata nonce", TorusUtils.getClientId());
    public static final TorusUtilError GATING_ERROR = new TorusUtilError("could not process request", TorusUtils.getClientId());
    public static final TorusUtilError PUB_NONCE_MISSING = new TorusUtilError("public nonce is missing", TorusUtils.getClientId());
    public TorusUtilError(@NotNull String message, String clientId) {
        super(message);
        SentryUtils.captureException(message + "_for client id: " + clientId);
        this.message = message;
    }

    private final String message;

    public static TorusUtilError RUNTIME_ERROR(@NotNull String msg)  {
        return new TorusUtilError(msg, TorusUtils.getClientId());
    }

    @Override
    public String toString() {
        return message;
    }

    @SuppressWarnings("unused")
    public String debugDescription() {
        return message;
    }

    public String getLocalizedMessage() {
        return message;
    }
}

