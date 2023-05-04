package org.fiware.gaiax.tir.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.util.X509CertUtils;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.gaiax.satellite.api.SatelliteApi;
import org.fiware.gaiax.satellite.model.TokenResponseVO;
import org.fiware.gaiax.tir.auth.JWTService;
import org.fiware.gaiax.tir.configuration.SatelliteProperties;
import org.fiware.gaiax.tir.configuration.TrustedCA;
import org.fiware.gaiax.tir.repository.PartiesRepo;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Controller("${general.basepath:/}")
@RequiredArgsConstructor
public class SatelliteController implements SatelliteApi {

	private static final String ALLOWED_GRANT_TYPE = "client_credentials";
	private static final String SCOPE_DELIMITER = " ";
	private static final String I_SHARE_SCOPE = "iSHARE";
	private static final String ALLOWED_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private final PartiesRepo partiesRepo;
	private final JWTService jwtService;
	private final SatelliteProperties satelliteProperties;

	@Secured({SecurityRule.IS_ANONYMOUS})
	@Override
	public HttpResponse<TokenResponseVO> getToken(String grantType, String clientId, String scope,
			String clientAssertionType, String clientAssertion) {
		if (!grantType.equals(ALLOWED_GRANT_TYPE)) {
			throw new IllegalArgumentException(String.format("Grant_type needs to be %s.", ALLOWED_GRANT_TYPE));
		}
		if (!Arrays.asList(scope.split(SCOPE_DELIMITER)).contains(I_SHARE_SCOPE)) {
			throw new IllegalArgumentException(String.format("Scope needs to contain %s.", I_SHARE_SCOPE));
		}
		if (!clientAssertionType.equals(ALLOWED_ASSERTION_TYPE)) {
			throw new IllegalArgumentException(String.format("Assertion type needs to be %s.", ALLOWED_ASSERTION_TYPE));
		}
		if (partiesRepo.getPartyById(clientId).isEmpty()) {
			throw new IllegalArgumentException(String.format("Unknown client %s", clientId));
		}
		jwtService.validateJWT(clientAssertion);
		TokenResponseVO tokenResponseVO = new TokenResponseVO()
				.accessToken(createToken(clientId))
				.expiresIn(3600)
				.scope(I_SHARE_SCOPE).tokenType("Bearer");
		return HttpResponse.ok(tokenResponseVO);
	}

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Override
	public HttpResponse<Object> getTrustedList() {
		return null;
	}

	private String createToken(String clientId) {
		Map<String, Object> header = Map.of("x5c", getPemChain());

		Algorithm signingAlgo = Algorithm.RSA256(
				(RSAPrivateKey) getPrivateKey(satelliteProperties.getKey()));
		return JWT.create()
				.withAudience(satelliteProperties.getId())
				.withIssuer(satelliteProperties.getId())
				.withClaim("client_id", clientId)
				.withClaim("jti", UUID.randomUUID().toString())
				.withNotBefore(Clock.systemUTC().instant())
				.withExpiresAt(Clock.systemUTC().instant().plus(Duration.of(30, ChronoUnit.MINUTES)))
				.withArrayClaim("scope", new String[] { I_SHARE_SCOPE })
				.withHeader(header)
				.sign(signingAlgo);

	}

	private static PrivateKey getPrivateKey(String key) {
		java.security.Security.addProvider(
				new org.bouncycastle.jce.provider.BouncyCastleProvider()
		);

		String privateKeyPEM = key
				.replace("-----BEGIN RSA PRIVATE KEY-----", "")
				.replaceAll(System.lineSeparator(), "")
				.replace("-----END RSA PRIVATE KEY-----", "");

		byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
			return keyFactory.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	private List<String> getPemChain() {
		X509CertUtils.parse(satelliteProperties.getCertificate());
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
				satelliteProperties.getCertificate().getBytes());
		CertificateFactory certificateFactory = null;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
			List<X509Certificate> x509Certificates = (List<X509Certificate>) certificateFactory.generateCertificates(
					byteArrayInputStream);
			return x509Certificates.stream().map(cert -> {
						try {
							return cert.getEncoded();
						} catch (CertificateEncodingException e) {
							log.info("Was not able to get the encoded cert.");
							return null;
						}
					})
					.map(certBytes -> Base64.getEncoder().encodeToString(certBytes)).toList();
		} catch (CertificateException e) {
			throw new IllegalArgumentException(e);
		}
	}





}
