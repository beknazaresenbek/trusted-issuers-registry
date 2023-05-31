package org.fiware.iam.tir.rest;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.exceptions.HttpClientResponseException;

import java.util.concurrent.Callable;

public abstract class TestUtils {
    public static String strip(String text){
        return text
                .replaceAll("\\n", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");
    }

    // Helper method to catch potential http exceptions and return the status code.
    public static <T> HttpResponse<T> callAndCatch(Callable<HttpResponse<T>> request) throws Exception {
        try {
            return request.call();
        } catch (HttpClientResponseException e) {
            return (HttpResponse<T>) e.getResponse();
        }
    }
}
