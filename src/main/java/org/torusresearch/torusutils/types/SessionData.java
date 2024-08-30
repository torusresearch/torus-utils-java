package org.torusresearch.torusutils.types;

import org.jetbrains.annotations.NotNull;
import org.torusresearch.torusutils.types.common.SessionToken;

import java.util.List;

public class SessionData {

    private final List<SessionToken> sessionTokenData;
    private final String sessionAuthKey;

    public SessionData(@NotNull List<SessionToken> sessionTokenData, @NotNull String sessionAuthKey) {
        this.sessionTokenData = sessionTokenData;
        this.sessionAuthKey = sessionAuthKey;
    }

    public List<SessionToken> getSessionTokenData() {
        return sessionTokenData;
    }
    public String getSessionAuthKey() {
        return sessionAuthKey;
    }
}
