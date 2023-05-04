package org.fiware.gaiax.tir.issuers;

import java.util.List;

public interface IssuersProvider {
    List<TrustedIssuer> getAllTrustedIssuers();
}
