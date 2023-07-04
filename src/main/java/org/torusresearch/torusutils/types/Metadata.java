package org.torusresearch.torusutils.types;

import java.math.BigInteger;

public class Metadata {

    public BigInteger metadataNonce;
    public TypeOfUser typeOfUser;
    public Boolean upgraded;

    public Metadata(BigInteger metadataNonce, TypeOfUser typeOfUser, Boolean upgraded) {
        this.metadataNonce = metadataNonce;
        this.typeOfUser = typeOfUser;
        this.upgraded = upgraded;
    }

    public BigInteger getMetadataNonce() {
        return metadataNonce;
    }

    public TypeOfUser getTypeOfUser() {
        return typeOfUser;
    }

    public Boolean getUpgraded() {
        return upgraded;
    }
}
