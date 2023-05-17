package org.fiware.iam.tir.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.inject.Singleton;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.configuration.SatelliteProperties;
import org.fiware.iam.tir.configuration.TrustedCA;
import org.fiware.iam.tir.repository.PartiesRepo;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Singleton
public class JWTService {

	private final PartiesRepo partiesRepo;
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
		try {
			JWT.require(Algorithm.RSA256((RSAPublicKey) publicKey)).build().verify(jwtString);
		} catch (JWTVerificationException jwtVerificationException) {
			throw new IllegalArgumentException("Token not verified.", jwtVerificationException);
		}
		Optional<String> optionalTrustedCA = satelliteProperties.getTrustedList().stream()
				.map(TrustedCA::crt)
				.map(this::getPem)
				.filter(caCert::equals)
				.findFirst();
		if (optionalTrustedCA.isEmpty()) {
			partiesRepo.getPartyById(decodedJWT.getClaim("iss").asString())
					.map(Party::crt)
					.map(JWTService::getPemChain)
					// get the client cert
					.map(parsedCerts -> parsedCerts.get(0))
					.filter(clientCert::equals)
					.orElseThrow(() -> new IllegalArgumentException("No trusted CA and no trusted party found."));
		}

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

	public static List<X509Certificate> getCertificates(String crt) {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
				crt.getBytes());
		CertificateFactory certificateFactory = null;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
			return (List<X509Certificate>) certificateFactory.generateCertificates(
					byteArrayInputStream);
		} catch (CertificateException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public static String getThumbprint(X509Certificate cert) throws CertificateEncodingException {
		MessageDigest sha256 = DigestUtils.getSha256Digest();
		return DatatypeConverter.printHexBinary(sha256.digest(cert.getEncoded()));
	}

	public static List<String> getPemChain(String crt) {

		return getCertificates(crt).stream().map(cert -> {
					try {
						return cert.getEncoded();
					} catch (CertificateEncodingException e) {
						log.info("Was not able to get the encoded cert.");
						return null;
					}
				})
				.map(certBytes -> Base64.getEncoder().encodeToString(certBytes)).toList();

	}

}
