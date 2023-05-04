package org.fiware.gaiax.tir.repository;

import io.micronaut.http.annotation.Part;
import org.fiware.gaiax.tir.configuration.Party;

import java.util.List;
import java.util.Optional;

public interface PartiesRepo {

	List<Party> getParties();
	Optional<Party> getPartyById(String id);
	Optional<Party> getPartyByDID(String did);
	void addParty(Party party);
}
