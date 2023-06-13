package org.torusresearch.torusutils.types;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class EciesHex {
    private Map<String, String> ecies;
    private Optional<String> mode;

    public EciesHex() {
        this.ecies = new HashMap<>();
    }

    public String getValue(String key) {
        return ecies.get(key);
    }

    public void setValue(String key, String value) {
        ecies.put(key, value);
    }

    public Optional<String> getMode() {
        return mode;
    }

    public void setMode(Optional<String> mode) {
        this.mode = mode;
    }
}
