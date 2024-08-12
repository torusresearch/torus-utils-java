package org.torusresearch.torusutils.types;

import org.torusresearch.torusutils.apis.requests.SetNonceData;

import java.util.Objects;

public class NonceMetadataParams {
    private String namespace;
    private String pubKeyX;
    private String pubKeyY;
    private SetNonceData setData;
    private TorusKeyType keyType;
    private String signature;
    private String encodedData;
    private String seed;

    public NonceMetadataParams(String pubKeyX, String pubKeyY, SetNonceData setData, String encodedData, String signature) {
        this.pubKeyX = pubKeyX;
        this.pubKeyY = pubKeyY;
        this.setData = setData;
        this.encodedData = encodedData;
        this.signature = signature;
    }

    public NonceMetadataParams(String pubKeyX, String pubKeyY, SetNonceData setData, String encodedData, String signature, String namespace, TorusKeyType keyType, String seed) {
        this.pubKeyX = pubKeyX;
        this.pubKeyY = pubKeyY;
        this.setData = setData;
        this.encodedData = encodedData;
        this.signature = signature;
        this.namespace = namespace;
        this.keyType = keyType;
        this.seed = seed;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getPubKeyX() {
        return pubKeyX;
    }

    public void setPubKeyX(String pubKeyX) {
        this.pubKeyX = pubKeyX;
    }

    public String getPubKeyY() {
        return pubKeyY;
    }

    public void setPubKeyY(String pubKeyY) {
        this.pubKeyY = pubKeyY;
    }

    public SetNonceData getSetData() {
        return setData;
    }

    public void setSetData(SetNonceData setData) {
        this.setData = setData;
    }

    public TorusKeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(TorusKeyType keyType) {
        this.keyType = keyType;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getEncodedData() {
        return encodedData;
    }

    public void setEncodedData(String encodedData) {
        this.encodedData = encodedData;
    }

    public String getSeed() {
        return seed;
    }

    public void setSeed(String seed) {
        this.seed = seed;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NonceMetadataParams that = (NonceMetadataParams) o;
        return Objects.equals(namespace, that.namespace) &&
                Objects.equals(pubKeyX, that.pubKeyX) &&
                Objects.equals(pubKeyY, that.pubKeyY) &&
                Objects.equals(setData, that.setData) &&
                keyType == that.keyType &&
                Objects.equals(signature, that.signature) &&
                Objects.equals(encodedData, that.encodedData) &&
                Objects.equals(seed, that.seed);
    }

    @Override
    public int hashCode() {
        return Objects.hash(namespace, pubKeyX, pubKeyY, setData, keyType, signature, encodedData, seed);
    }

    @Override
    public String toString() {
        return "NonceMetadataParams{" +
                "namespace='" + namespace + '\'' +
                ", pubKeyX='" + pubKeyX + '\'' +
                ", pubKeyY='" + pubKeyY + '\'' +
                ", setData=" + setData +
                ", keyType=" + keyType +
                ", signature='" + signature + '\'' +
                ", encodedData='" + encodedData + '\'' +
                ", seed='" + seed + '\'' +
                '}';
    }
}

