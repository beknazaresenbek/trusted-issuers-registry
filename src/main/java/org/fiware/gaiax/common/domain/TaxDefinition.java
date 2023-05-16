package org.fiware.gaiax.common.domain;

import lombok.Data;

@Data
public class TaxDefinition {

	private String id;
	private String name;
	private String taxType;
	private String atBaseType;
	private String atSchemaLocation;
	private String atType;
	private String atReferredType;

}
