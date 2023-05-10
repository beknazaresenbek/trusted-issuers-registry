package org.fiware.gaiax.tir.repository;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.fiware.tmforum.mapping.annotations.Ignore;

import java.util.List;

@Data
public class DidDocument {

	private List<Object> assertionMethod;
	private List<Object> authentication;
	@JsonProperty("@context")
	private List<String> context;
	private String id;
	private List<VerificationMethod> verificationMethod;
}
