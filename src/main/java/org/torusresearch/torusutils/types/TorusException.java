package org.torusresearch.torusutils.types;

public class TorusException extends Exception {
    public TorusException(String msg) {
        super(msg);
    }

    public TorusException(String msg, Throwable err) {
        super(msg, err);
    }
}
