package org.torusresearch.torusutils.apis;

public class Index {

    private String index;
    private String service_group_id;
    private String region;
    private String tag;
    private long randomness;


    public Index(String index, String service_group_id, String region, String tag, long randomness) {
        this.index = index;
        this.service_group_id = service_group_id;
        this.region = region;
        this.tag = tag;
        this.randomness = randomness;
    }

    public String getIndex() {
        return index;
    }

    public String getService_group_id() {
        return service_group_id;
    }

    public String getRegion() {
        return region;
    }

    public String getTag() {
        return tag;
    }

    public long getRandomness() {
        return randomness;
    }
}
