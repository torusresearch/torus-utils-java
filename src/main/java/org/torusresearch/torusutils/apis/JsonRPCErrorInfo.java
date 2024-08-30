package org.torusresearch.torusutils.apis;

public class JsonRPCErrorInfo {
        public final int code;
        public final String message;
        public final Object data;

        public JsonRPCErrorInfo(int code, String message, Object data) {
            this.code = code;
            this.message = message;
            this.data = data;
        }
}
