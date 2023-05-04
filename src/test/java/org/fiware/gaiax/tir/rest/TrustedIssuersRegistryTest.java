package org.fiware.gaiax.tir.rest;


import io.micronaut.http.HttpResponse;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.fiware.gaiax.tir.api.TirApiTestClient;
import org.fiware.gaiax.tir.api.TirApiTestSpec;
import org.fiware.gaiax.tir.model.IssuerVO;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
@MicronautTest
class TrustedIssuersRegistryTest implements TirApiTestSpec {


    @Inject
    private TirApiTestClient testClient;

    @Test
    @Override
    public void getIssuer200() throws Exception {

        HttpResponse<IssuerVO> response = testClient.getIssuer("someDid");
        assertEquals(response.body(),new IssuerVO().did("someD2id")); // should fail
    }

    @Override
    public void getIssuer400() throws Exception {

    }

    @Override
    public void getIssuer404() throws Exception {

    }

    @Override
    public void getIssuer500() throws Exception {

    }

    @Override
    public void getIssuers200() throws Exception {

    }

    @Override
    public void getIssuers400() throws Exception {

    }

    @Override
    public void getIssuers500() throws Exception {

    }
}