package org.torusresearch.torusutilstest;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.torusresearch.fetchnodedetails.FetchNodeDetails;
import org.torusresearch.fetchnodedetails.types.NodeDetails;
import org.torusresearch.torusutils.TorusUtils;
import org.torusresearch.torusutils.types.TorusPublicKey;
import org.torusresearch.torusutils.types.VerifierArgs;

import java.util.Arrays;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TorusUtilsTest {

    static NodeDetails nodeDetails;

    @BeforeAll
    static void setup() throws ExecutionException, InterruptedException {
        System.out.println("Setup Starting");
        FetchNodeDetails fetchNodeDetails = new FetchNodeDetails();
        nodeDetails = fetchNodeDetails.getNodeDetails().get();
    }

    @DisplayName("Gets Public Address")
    @Test
    public void shouldGetPublicAddress() throws ExecutionException, InterruptedException {
        VerifierArgs args = new VerifierArgs("google", "hello@tor.us");
        System.out.println("Starting test");
        Arrays.stream(nodeDetails.getTorusNodeEndpoints()).forEach(System.out::println);
        Arrays.stream(nodeDetails.getTorusNodePub()).forEach(System.out::println);
        TorusPublicKey publicAddress = TorusUtils.getPublicAddress(nodeDetails.getTorusNodeEndpoints(), nodeDetails.getTorusNodePub(), args).get();
        System.out.println(publicAddress.getAddress());
        assertEquals("0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A", publicAddress.getAddress());
    }
}
