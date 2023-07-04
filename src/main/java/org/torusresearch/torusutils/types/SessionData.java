package org.torusresearch.torusutils.types;

import java.util.List;

public class SessionData {

    public List<SessionToken> sessionTokenData;
    public String sessionAuthKey;

    public SessionData(List<SessionToken> sessionTokenData, String sessionAuthKey) {
        this.sessionTokenData = sessionTokenData;
        this.sessionAuthKey = sessionAuthKey;
    }

    public List<SessionToken> getSessionTokenData() {
        return sessionTokenData;
    }

    public void setSessionTokenData(List<SessionToken> sessionTokenData) {
        this.sessionTokenData = sessionTokenData;
    }

    public String getSessionAuthKey() {
        return sessionAuthKey;
    }

    public void setSessionAuthKey(String sessionAuthKey) {
        this.sessionAuthKey = sessionAuthKey;
    }
}
