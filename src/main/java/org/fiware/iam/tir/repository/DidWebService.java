package org.fiware.iam.tir.repository;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientException;
import lombok.RequiredArgsConstructor;
import org.fiware.iam.did.model.DIDDocumentVO;
import org.fiware.iam.did.model.JWKVO;
import org.fiware.iam.did.model.JsonWebKey2020VerificationMethodVO;

import javax.inject.Singleton;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Optional;

/**
 * Handle resolving DID's according to [DID:Web]{https://w3c-ccg.github.io/did-method-web/#create-register}
 */
@RequiredArgsConstructor
@Singleton
public class DidWebService implements DidService {

    private final HttpClient httpClient;

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<DIDDocumentVO> retrieveDidDocument(String did) {
        String documentPath = getDIDDocumentPath(did);
        HttpResponse<DIDDocumentVO> res = httpClient.toBlocking()
                .exchange(documentPath, DIDDocumentVO.class);
        return Optional.ofNullable(res).filter(response -> response.status() == HttpStatus.OK).map(HttpResponse::body);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<String> getCertificate(DIDDocumentVO didDocument) {
        try {
            return Optional
                    .ofNullable(didDocument.getVerificationMethod())
                    .orElseGet(ArrayList::new)
                    .stream()
                    // Todo handle other types
                    .filter(e-> e instanceof JsonWebKey2020VerificationMethodVO)
                    .map(e-> (JsonWebKey2020VerificationMethodVO)e)
                    .map(JsonWebKey2020VerificationMethodVO::getPublicKeyJwk)
                    .filter(Objects::nonNull)
                    .map(JWKVO::getX5u)
                    .filter(Objects::nonNull)
                    .map(certificateAddress -> httpClient.toBlocking().retrieve(certificateAddress))
                    .findFirst();
        } catch (HttpClientException e) {
            throw new IllegalArgumentException("Could not retrieve certificate for did %s".formatted(didDocument.getId()), e);
        }
    }

    private String getDIDDocumentPath(String did) {
        String[] didParts = did.split(":");
        if (didParts.length < 3) {
            throw new IllegalArgumentException("Did must be at least 3 segments big.");
        }
        // Decode optional port usage
        didParts[2] = URLDecoder.decode(didParts[2], StandardCharsets.UTF_8);

        if (!didParts[1].equals("web")) {
            throw new IllegalArgumentException("Only did web is supported.");
        }

        if (didParts.length == 3) {
            // standard well-known path
            return String.format("https://%s/.well-known/did.json", didParts[2]);
        }
        String documentPath = "https://" + didParts[2];

        for (int i = 3; i < didParts.length; i++) {
            documentPath += "/" + didParts[i];
        }
        documentPath += "/did.json";
        return documentPath;

    }
}
