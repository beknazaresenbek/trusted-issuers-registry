package org.fiware.iam.tir.rest;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.tir.api.TirApi;
import org.fiware.iam.tir.issuers.IssuersProvider;
import org.fiware.iam.tir.issuers.TrustedIssuerMapper;
import org.fiware.iam.tir.model.IssuerVO;
import org.fiware.iam.tir.model.IssuersResponseVO;

import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
@Controller("${general.basepath:/}")
@Secured(SecurityRule.IS_ANONYMOUS)
public class TrustedIssuersRegistry implements TirApi {
    private final IssuersProvider issuersProvider;
    private final TrustedIssuerMapper mapper;

    @Override
    public HttpResponse<IssuerVO> getIssuer(String did) {

        Optional<IssuerVO> foundIssuer = issuersProvider
                .getAllTrustedIssuers()
                .stream()
                .filter(issuer -> issuer.getIssuer().equalsIgnoreCase(did))
                .map(mapper::map).findAny();
       if(foundIssuer.isPresent()){
           return HttpResponse.ok(foundIssuer.get());
       }else{
           return HttpResponse.notFound();
       }
    }

    @Override
    public HttpResponse<IssuersResponseVO> getIssuers(@Nullable Double pageSize, @Nullable String pageAfter) {
        return HttpResponse.ok(mapper.map(issuersProvider
                .getAllTrustedIssuers()));
    }
}
