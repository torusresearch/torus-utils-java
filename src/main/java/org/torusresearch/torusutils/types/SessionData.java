package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.types.common.SessionToken;

import java.util.List;

public class SessionData {

    public final List<SessionToken> sessionTokenData;
    public final String sessionAuthKey;

    public SessionData(List<SessionToken> sessionTokenData, String sessionAuthKey) {
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
