package org.fiware.iam.tir.issuers;

import org.fiware.iam.common.mapping.IdHelper;
import org.fiware.iam.tir.model.IssuerAttributeVO;
import org.fiware.iam.tir.model.IssuerEntryVO;
import org.fiware.iam.tir.model.IssuerVO;
import org.fiware.iam.tir.model.IssuersResponseVO;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "jsr330", uses = IdHelper.class)
public interface TrustedIssuerMapper {

    default IssuerVO map(TrustedIssuer trustedIssuer){
        return new IssuerVO().did(trustedIssuer.getIssuer()).addAttributesItem(new IssuerAttributeVO().body("ab").hash("ab"));

    }

    default IssuersResponseVO map(List<TrustedIssuer> issuers) {
        IssuersResponseVO responseVO = new IssuersResponseVO();
        issuers.forEach(issuer -> responseVO.addItemsItem(new IssuerEntryVO().did(issuer.getIssuer())));
        responseVO.setPageSize((double) issuers.size());
        responseVO.setTotal((double) issuers.size());
        return responseVO;
    }

}
