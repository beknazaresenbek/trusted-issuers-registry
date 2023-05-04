package org.fiware.gaiax.tir.issuers;

import org.fiware.gaiax.tir.model.IssuerEntryVO;
import org.fiware.gaiax.tir.model.IssuerVO;
import org.fiware.gaiax.tir.model.IssuersResponseVO;
import org.fiware.tmforum.common.mapping.IdHelper;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.List;

@Mapper(componentModel = "jsr330", uses = IdHelper.class)
public interface TrustedIssuerMapper {
    @Mapping(source = "issuer", target = "did")
    IssuerVO map(TrustedIssuer trustedIssuer);

    default IssuersResponseVO map(List<TrustedIssuer> issuers) {
        IssuersResponseVO responseVO = new IssuersResponseVO();
        issuers.forEach(issuer -> responseVO.addItemsItem(new IssuerEntryVO().did(issuer.getIssuer())));
        responseVO.setPageSize((double) issuers.size());
        responseVO.setTotal((double) issuers.size());
        return responseVO;
    }

}
