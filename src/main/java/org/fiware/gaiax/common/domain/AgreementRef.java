package org.fiware.gaiax.common.domain;

import io.github.wistefan.mapping.annotations.MappingEnabled;
import lombok.EqualsAndHashCode;

import java.util.List;

@EqualsAndHashCode(callSuper = true)
@MappingEnabled
public class AgreementRef extends RefEntity {

	public AgreementRef(String id) {
		super(id);
	}

	@Override
	public List<String> getReferencedTypes() {
		return List.of("agreement");
	}

}
