package org.fiware.gaiax.tir.repository;

import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.fiware.gaiax.tir.configuration.Party;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
public class InMemoryPartiesRepo implements PartiesRepo {

	private final List<Party> parties;

	@Override public List<Party> getParties() {
		return parties;
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
