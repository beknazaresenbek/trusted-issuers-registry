package org.fiware.gaiax.common.domain;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ContactMedium extends Entity {

	private String mediumType;
	private boolean preferred;
	private MediumCharacteristic characteristic;
	private TimePeriod validFor;

}
