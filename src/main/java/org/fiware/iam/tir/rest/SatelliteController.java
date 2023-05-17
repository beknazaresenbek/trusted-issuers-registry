package org.fiware.iam.tir.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.utils.SecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.satellite.api.SatelliteApi;
import org.fiware.iam.satellite.model.AdherenceVO;
import org.fiware.iam.satellite.model.CertificateVO;
import org.fiware.iam.satellite.model.PartiesInfoVO;
import org.fiware.iam.satellite.model.PartiesResponseVO;
import org.fiware.iam.satellite.model.PartyInfoVO;
import org.fiware.iam.satellite.model.PartyResponseVO;
import org.fiware.iam.satellite.model.PartyVO;
import org.fiware.iam.satellite.model.TokenResponseVO;
import org.fiware.iam.satellite.model.TrustedListResponseVO;
import org.fiware.iam.tir.auth.JWTService;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.configuration.SatelliteProperties;
import org.fiware.iam.tir.repository.PartiesRepo;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Controller("${general.basepath:/}")
@RequiredArgsConstructor
public class SatelliteController implements SatelliteApi {

	private static final String ALLOWED_GRANT_TYPE = "client_credentials";
	private static final String SCOPE_DELIMITER = " ";
	private static final String I_SHARE_SCOPE = "iSHARE";
	private static final String ALLOWED_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	private final PartiesRepo partiesRepo;
	private final JWTService jwtService;
	private final SatelliteProperties satelliteProperties;
	private final SecurityService securityService;

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Override
	public HttpResponse<PartiesResponseVO> getParties(String eori, String certificateSubjectName) {
		Optional<String> optionalEori = Optional.ofNullable(eori);
		Optional<String> optionalCSN = Optional.ofNullable(certificateSubjectName);
		List<Party> partys = new ArrayList<>();
		if (optionalEori.isPresent()) {
			partiesRepo.getPartyById(optionalEori.get()).ifPresent(party -> partys.add(party));
		} else {
			partys.addAll(partiesRepo.getParties());
		}
		if (optionalCSN.isPresent()) {
			List<Party> updatedParties = new ArrayList<>();
			partys.stream().forEach(party -> {
				var clientCert = JWTService.getCertificates(party.crt()).get(0);
				if (clientCert.getSubjectX500Principal().getName().equals(optionalCSN.get())) {
					updatedParties.add(party);
				}
			});
			partys.clear();
			partys.addAll(updatedParties);
		}

		List<PartyVO> partyVOS = partys.stream()
				.map(this::partyToPartyVO)
				.collect(Collectors.toList());

		PartiesInfoVO partiesInfoVO = new PartiesInfoVO().data(partyVOS).count(partyVOS.size());

		return HttpResponse.ok(new PartiesResponseVO().partiesToken(
				createToken(securityService.getAuthentication().map(Principal::getName),
						Optional.empty(),
						Map.of(),
						Map.of("parties_info", OBJECT_MAPPER.convertValue(partiesInfoVO, Map.class)))));
	}

	private PartyVO partyToPartyVO(Party party) {
		// we need only the first one, the client
		X509Certificate certificate = jwtService.getCertificates(party.crt()).get(0);

		PartyVO partyVO = new PartyVO();
		partyVO.partyId(party.id())
				.partyName(party.name())
				.adherence(new AdherenceVO().status("Active"));
		toCertificateVO(certificate).ifPresent(c -> partyVO.certificates(List.of(c)));
		return partyVO;
	}

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Override
	public HttpResponse<PartyResponseVO> getPartyById(String partyId) {
		Optional<PartyVO> optionalParty = partiesRepo.getPartyById(partyId).map(this::partyToPartyVO);
		if (optionalParty.isEmpty()) {
			return HttpResponse.notFound();
		}
		PartyInfoVO partyInfoVO = new PartyInfoVO().partyInfo(optionalParty.get());

		return HttpResponse.ok(new PartyResponseVO().partyToken(
				createToken(securityService.getAuthentication().map(Principal::getName),
						Optional.empty(),
						Map.of(),
						Map.of("parties_token", OBJECT_MAPPER.convertValue(partyInfoVO, Map.class)))));
	}

	private Optional<CertificateVO> toCertificateVO(X509Certificate certificate) {
		try {

			return Optional.of(new CertificateVO()
					.certificateType(certificate.getType())
					.enabledFrom(certificate.getNotBefore().toString())
					.subjectName(certificate.getSubjectX500Principal().getName())
					.x5c(Base64.getEncoder().encodeToString(certificate.getEncoded()))
					.x5tHashS256(JWTService.getThumbprint(certificate)));
		} catch (CertificateEncodingException e) {
			log.warn("Was not able to encode cert.", e);
			return Optional.empty();
		}
	}

	@Secured({ SecurityRule.IS_ANONYMOUS })
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
			throw new IllegalArgumentException(
					String.format("Assertion type needs to be %s.", ALLOWED_ASSERTION_TYPE));
		}
		if (partiesRepo.getPartyById(clientId).isEmpty()) {
			log.debug("Known parties: {}.", partiesRepo.getParties().stream().map(Party::id).toList());
			throw new IllegalArgumentException(String.format("Unknown client %s", clientId));
		}
		jwtService.validateJWT(clientAssertion);
		TokenResponseVO tokenResponseVO = new TokenResponseVO()
				.accessToken(createToken(Optional.empty(), Optional.of(clientId), Map.of(), Map.of()))
				.expiresIn(3600)
				.scope(I_SHARE_SCOPE).tokenType("Bearer");
		return HttpResponse.ok(tokenResponseVO);
	}

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Override
	public HttpResponse<TrustedListResponseVO> getTrustedList() {

		return HttpResponse.ok(new TrustedListResponseVO().trustedListToken(
				createToken(securityService.getAuthentication().map(Principal::getName),
						Optional.empty(),
						Map.of("trusted_list", partiesRepo.getTrustedCAs()), Map.of())));
	}

	private String createToken(Optional<String> aud, Optional<String> clientId, Map<String, List<?>>
			additionalClaims, Map<String, Map> mapClaim) {
		Map<String, Object> header = Map.of("x5c", jwtService.getPemChain(satelliteProperties.getCertificate()));

		Algorithm signingAlgo = Algorithm.RSA256(
				(RSAPrivateKey) getPrivateKey(satelliteProperties.getKey()));

		JWTCreator.Builder jwtBuilder = JWT.create()
				.withAudience(satelliteProperties.getId())
				.withIssuer(satelliteProperties.getId())
				.withSubject(satelliteProperties.getId())
				.withClaim("jti", UUID.randomUUID().toString())
				.withNotBefore(Clock.systemUTC().instant())
				.withExpiresAt(Clock.systemUTC().instant().plus(Duration.of(30, ChronoUnit.MINUTES)))
				.withArrayClaim("scope", new String[] { I_SHARE_SCOPE })
				.withHeader(header);
		aud.ifPresent(jwtBuilder::withAudience);
		clientId.ifPresent(ci -> jwtBuilder.withClaim("client_id", ci));
		if (!additionalClaims.isEmpty()) {
			additionalClaims.entrySet().forEach(entry ->
					jwtBuilder.withClaim(entry.getKey(),
							entry.getValue().stream().map(v -> OBJECT_MAPPER.convertValue(v, Map.class))
									.collect(Collectors.toList())));
		}
		if (!mapClaim.isEmpty()) {
			mapClaim.entrySet().forEach(entry -> jwtBuilder.withClaim(entry.getKey(), entry.getValue()));
		}

		return jwtBuilder.sign(signingAlgo);

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

}
