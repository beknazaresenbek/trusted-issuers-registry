package org.fiware.gaiax.common.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.EqualsAndHashCode;

import java.util.List;

@EqualsAndHashCode(callSuper = true)
public class BillingAccountRef extends RefEntity {

	public BillingAccountRef(String id) {
		super(id);
	}

	@Override
	@JsonIgnore
	public List<String> getReferencedTypes() {
		return List.of("billing-account");
	}
}
