package org.fiware.gaiax.common.domain;

import lombok.Data;

import java.net.URI;

@Data
public class TaxItem {

	private String id;
	private URI href;
	private String taxCategory;
	private Float taxRate;
	private Money taxAmount;
	private String atBaseType;
	private URI atSchemaLocation;
	private String atType;
}
