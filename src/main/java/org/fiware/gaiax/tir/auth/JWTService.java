package org.fiware.gaiax.tir.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.micronaut.context.annotation.Replaces;
import jakarta.inject.Singleton;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.gaiax.tir.configuration.SatelliteProperties;
import org.fiware.gaiax.tir.configuration.TrustedCA;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Singleton
public class JWTService {

	private final SatelliteProperties satelliteProperties;

	public DecodedJWT validateJWT(String jwtString) {
		DecodedJWT decodedJWT = JWT.decode(jwtString);
		List<String> certs = decodedJWT.getHeaderClaim("x5c").asList(String.class);
		if (certs.size() != 3) {
			throw new IllegalArgumentException("Did not receive a full x5c chain.");
		}
		String clientCert = certs.get(0);
		String caCert = certs.get(2);
		PublicKey publicKey = getPublicKey(clientCert);
		JWT.require(Algorithm.RSA256((RSAPublicKey) publicKey)).build().verify(jwtString);
		satelliteProperties.getTrustedList().stream()
				.map(TrustedCA::crt)
				.map(this::getPem)
				.filter(pem -> pem.equals(caCert))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException("The ca is not trusted."));
		return decodedJWT;
	}

	public static PublicKey getPublicKey(String pemBlock) {

		byte[] keyBytes = Base64.getDecoder().decode(pemBlock);
		try {
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			X509Certificate cer = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(keyBytes));
			return cer.getPublicKey();
		} catch (CertificateException e) {
			log.warn("Was not able to parse the key", e);
			throw new RuntimeException("Was not able to parse the key.", e);
		}
	}


	private String getPem(String cert) {
		return cert.replace("-----BEGIN CERTIFICATE-----", "")
				.replace("-----END CERTIFICATE-----", "")
				.replaceAll("\\s", "");
	}

}
