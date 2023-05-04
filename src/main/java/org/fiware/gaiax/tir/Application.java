package org.fiware.gaiax.tir;

import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.runtime.Micronaut;
import org.fiware.gaiax.tir.configuration.SatelliteProperties;
import org.fiware.gaiax.tir.repository.InMemoryPartiesRepo;
import org.fiware.gaiax.tir.repository.PartiesRepo;

@Factory
public class Application {

	public static void main(String[] args) {
		Micronaut.run(Application.class, args);
	}

	@Bean
	public PartiesRepo partiesRepo(SatelliteProperties satelliteProperties) {
		return new InMemoryPartiesRepo(satelliteProperties.getParties());
	}
}
