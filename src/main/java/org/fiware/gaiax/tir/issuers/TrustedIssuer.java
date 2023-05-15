package org.fiware.gaiax.tir.issuers;

import io.github.wistefan.mapping.annotations.AttributeGetter;
import io.github.wistefan.mapping.annotations.AttributeSetter;
import io.github.wistefan.mapping.annotations.AttributeType;
import io.github.wistefan.mapping.annotations.MappingEnabled;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.fiware.tmforum.common.domain.EntityWithId;

/**
 * Example data
 * [
 * {
 * "@context": "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#",
 * "id": "urn:ngsi-ld:TrustedIssuer:did:web:animalgoods.gaia-x.fiware.dev:did",
 * "type": "TrustedIssuer",
 * "issuer": {
 * "type": "Property",
 * "value": "did:web:animalgoods.gaia-x.fiware.dev:did"
 * },
 * "selfDescription": {
 * "type": "Property",
 * "value": {
 * "gx-terms-and-conditions:gaiaxTermsAndConditions": "70c1d713215f95191a11d38fe2341faed27d19e083917bc8732ca4fea4976700",
 * "gx:headquarterAddress": {
 * "gx:countrySubdivisionCode": "BE-BRU"
 * },
 * "gx:legalAddress": {
 * "gx:countrySubdivisionCode": "BE-BRU"
 * },
 * "gx:legalName": "Animal Goods Org.",
 * "gx:legalRegistrationNumber": {
 * "gx:vatID": "MYVATID"
 * },
 * "id": "did:web:animalgoods.gaia-x.fiware.dev:did",
 * "type": "gx:LegalParticipant"
 * }
 * }
 * }
 * ]
 */
@EqualsAndHashCode(callSuper = true)
@MappingEnabled(entityType = TrustedIssuer.TYPE_TRUSTED_ISSUER)
public class TrustedIssuer extends EntityWithId {

    public static final String TYPE_TRUSTED_ISSUER = "TrustedIssuer";

    @Getter(onMethod = @__({@AttributeGetter(value = AttributeType.PROPERTY, targetName = "issuer")}))
    @Setter(onMethod = @__({@AttributeSetter(value = AttributeType.PROPERTY, targetName = "issuer")}))
    private String issuer;

    @Getter(onMethod = @__({@AttributeGetter(value = AttributeType.PROPERTY, targetName = "selfDescription")}))
    @Setter(onMethod = @__({@AttributeSetter(value = AttributeType.PROPERTY, targetName = "selfDescription")}))
    private SelfDescription selfDescription;

    public TrustedIssuer(String id) {
        super(TYPE_TRUSTED_ISSUER, id);
    }

    @AllArgsConstructor
    @NoArgsConstructor
    public static class SelfDescription {
        @Getter(onMethod = @__({@AttributeGetter(value = AttributeType.PROPERTY, targetName = "gx:legalName")}))
        @Setter(onMethod = @__({@AttributeSetter(value = AttributeType.PROPERTY, targetName = "gx:legalName")}))
        private String legalName;
    }
}
