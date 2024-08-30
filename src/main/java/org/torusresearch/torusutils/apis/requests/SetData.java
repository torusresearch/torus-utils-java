package org.torusresearch.torusutils.apis.requests;

import org.jetbrains.annotations.NotNull;

public class SetData {
        public final String data;
        public final String timestamp;

        public SetData(@NotNull String data, @NotNull String timestamp) {
            this.data = data;
            this.timestamp = timestamp;
        }
}
