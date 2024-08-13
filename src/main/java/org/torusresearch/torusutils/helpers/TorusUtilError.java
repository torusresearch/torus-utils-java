package org.torusresearch.torusutils.helpers;
// TODO: Properly use and return all error types where applicable
public class TorusUtilError extends Exception {

    // Define error cases
    public static final TorusUtilError CONFIGURATION_ERROR = new TorusUtilError("SDK Configuration incorrect. Network is probably incorrect");
    public static final TorusUtilError COMMITMENT_REQUEST_FAILED = new TorusUtilError("commitment request failed");
    public static final TorusUtilError DECRYPTION_FAILED = new TorusUtilError("Decryption Failed");
    public static final TorusUtilError ENCODING_FAILED = new TorusUtilError("Could not encode data");
    public static final TorusUtilError DECODING_FAILED = new TorusUtilError("JSON Decoding error");
    public static final TorusUtilError IMPORT_SHARE_FAILED = new TorusUtilError("import share failed");
    public static final TorusUtilError PRIVATE_KEY_DERIVE_FAILED = new TorusUtilError("could not derive private key");
    public static final TorusUtilError INTERPOLATION_FAILED = new TorusUtilError("lagrange interpolation failed");
    public static final TorusUtilError INVALID_KEY_SIZE = new TorusUtilError("Invalid key size. Expected 32 bytes");
    public static final TorusUtilError INVALID_PUB_KEY_SIZE = new TorusUtilError("Invalid key size. Expected 64 bytes");
    public static final TorusUtilError RUNTIME_ERROR = new TorusUtilError("runtime error");
    public static final TorusUtilError RETRIEVE_OR_IMPORT_SHARE_ERROR = new TorusUtilError("retrieve or import share failed");
    public static final TorusUtilError METADATA_NONCE_MISSING = new TorusUtilError("Unable to fetch metadata nonce");
    public static final TorusUtilError GATING_ERROR = new TorusUtilError("could not process request");

    private String message;

    // Constructor with message
    public TorusUtilError(String message) {
        super(message);
        this.message = message;
    }

    // Override toString to provide the error message
    @Override
    public String toString() {
        return message;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof TorusUtilError) {
            return ((TorusUtilError) obj).message.equals(message);
        }
        return false;
    }

    public String debugDescription() {
        return message;
    }

    public String getLocalizedMessage() {
        return message;
    }
}

