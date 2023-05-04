package org.fiware.gaiax.tir.rest;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import lombok.extern.slf4j.Slf4j;
import org.fiware.gaiax.tir.api.TirApi;
import org.fiware.gaiax.tir.model.IssuerVO;
import org.fiware.gaiax.tir.model.IssuersResponseVO;

@Slf4j
@Controller("${general.basepath:/}")
public class TrustedIssuersRegistry implements TirApi {
    @Override
    public HttpResponse<IssuerVO> getIssuer(String did) {
        return HttpResponse.ok(new IssuerVO().did(did));
    }

    @Override
    public HttpResponse<IssuersResponseVO> getIssuers(Double pageSize, String pageAfter) {
        return HttpResponse.ok(new IssuersResponseVO());
    }
}
