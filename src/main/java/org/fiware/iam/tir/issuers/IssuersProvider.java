package org.fiware.iam.tir.issuers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.common.repository.TrustedIssuersRepository;
import reactor.core.publisher.Mono;

import javax.inject.Singleton;
import java.time.Duration;
import java.util.List;

@Slf4j
@Singleton
@RequiredArgsConstructor
public class IssuersProvider {

    private final TrustedIssuersRepository vcRepository;

    public List<TrustedIssuer> getAllTrustedIssuers() {
        Mono<List<TrustedIssuer>> entities = vcRepository.findEntities(0, 1000, TrustedIssuer.TYPE_TRUSTED_ISSUER,
                TrustedIssuer.class);
        return entities.block(Duration.ofSeconds(30));
    }

}
