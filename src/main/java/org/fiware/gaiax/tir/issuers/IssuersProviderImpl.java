package org.fiware.gaiax.tir.issuers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.tmforum.common.repository.TmForumRepository;
import reactor.core.publisher.Mono;

import javax.inject.Singleton;
import java.time.Duration;
import java.util.List;

@Slf4j
@Singleton // Not really a singleton but didn't inject. Whats equivalent to @Component from SpringBoot? Do I really have to manually create a bean?
@RequiredArgsConstructor
public class IssuersProviderImpl implements IssuersProvider {

    private final TmForumRepository vcRepository;

    @Override
    public List<TrustedIssuer> getAllTrustedIssuers() {
        try {
            Mono<List<TrustedIssuer>> entities = vcRepository.findEntities(0, 1000, TrustedIssuer.TYPE_TRUSTED_ISSUER, TrustedIssuer.class);
            return entities.block(Duration.ofSeconds(30));
        }catch(Exception e){
            log.error("Failed getting issuers",e);
            throw e;
        }
    }
}
