package org.fiware.iam.tir.repository;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.HttpClient;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.satellite.model.TrustedCAVO;
import org.fiware.iam.tir.auth.JWTService;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.configuration.SatelliteProperties;
import org.fiware.iam.tir.issuers.IssuersProvider;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Singleton
public class InMemoryPartiesRepo implements PartiesRepo {

	private final SatelliteProperties satelliteProperties;
	private final IssuersProvider issuersProvider;
	private final List<Party> parties;
	private final HttpClient httpClient;

	public InMemoryPartiesRepo(SatelliteProperties satelliteProperties, IssuersProvider issuersProvider,
			HttpClient httpClient) {
		this.parties = satelliteProperties.getParties();
		this.satelliteProperties = satelliteProperties;
		this.issuersProvider = issuersProvider;
		this.httpClient = httpClient;
	}

	private Optional<TrustedCAVO> toTrustedCaVO(X509Certificate caCert) {

		try {
			String subject = caCert.getSubjectX500Principal().toString();
			String validity = isValid(caCert);
			String fingerprint = JWTService.getThumbprint(caCert);
			return Optional.of(new TrustedCAVO().status("granted").certificateFingerprint(fingerprint)
					.validity(validity).subject(subject));
		} catch (CertificateEncodingException e) {
			log.warn("Was not able to get the fingerprint.");
		}
		return Optional.empty();
	}

	private String isValid(X509Certificate cert) {
		try {
			cert.checkValidity();
			return "valid";
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			return "invalid";
		}
	}

	@Scheduled(fixedDelay = "15s")
	public void updateParties() {
		List<Party> updatedParties = new ArrayList<>();
		updatedParties.addAll(satelliteProperties.getParties());

		issuersProvider.getAllTrustedIssuers().stream().forEach(ti -> {
			try {
				String documentPath = getDIDDocumentPath(ti.getIssuer());
				HttpResponse<DidDocument> res = httpClient.toBlocking()
						.exchange(documentPath, DidDocument.class);
				if (res.status() == HttpStatus.OK) {
					DidDocument didDocument = res.body();
					Optional<VerificationMethod> x5uVM = didDocument
							.getVerificationMethod()
							.stream()
							.filter(vm -> vm.getPublicKeyJwk().getX5u() != null).findFirst();
					String certificateAddress = x5uVM.get().getPublicKeyJwk().getX5u();
					String cert = httpClient.toBlocking().retrieve(certificateAddress);
					updatedParties.add(
							new Party(didDocument.getId(), didDocument.getId(), didDocument.getId(), "active", cert));
				}
			} catch (IllegalArgumentException e) {
				log.warn("Cannot resolve issuer {}, skip.", ti.getIssuer());
			}
		});
		parties.clear();
		parties.addAll(updatedParties);
	}

	// port not supported yet
	private String getDIDDocumentPath(String did) {
		String[] didParts = did.split(":");
		if (!didParts[1].equals("web")) {
			throw new IllegalArgumentException("Only did web is supported.");
		}
		if (didParts.length == 3) {
			// standard well-known path
			return String.format("https://%s/.well-known/did.json", didParts[2]);
		}
		String documentPath = "https://" + didParts[2];

		for (int i = 3; i < didParts.length; i++) {
			documentPath += "/" + didParts[i];
		}
		documentPath += "/did.json";
		return documentPath;

	}

	@Override public List<Party> getParties() {
		return parties;
	}

	@Override public List<TrustedCAVO> getTrustedCAs() {
		List<TrustedCAVO> trustedCAVOS = new ArrayList<>();

		satelliteProperties.getTrustedList().stream()
				.forEach(trustedCA -> {
					toTrustedCaVO(JWTService.getCertificates(trustedCA.crt()).get(0)).ifPresent(
							trustedCAVOS::add);
				});

		return trustedCAVOS;
	}

	@Override public Optional<Party> getPartyById(String id) {
		return parties.stream().filter(party -> party.id().equals(id)).findFirst();
	}

	@Override public Optional<Party> getPartyByDID(String did) {
		return parties.stream().filter(party -> party.did().equals(did)).findFirst();
	}

	@Override public void addParty(Party party) {

	}
}
