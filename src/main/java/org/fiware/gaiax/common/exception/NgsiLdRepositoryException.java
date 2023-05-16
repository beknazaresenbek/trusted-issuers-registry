package org.fiware.gaiax.common.exception;

import lombok.Getter;
import org.fiware.gaiax.common.repository.NgsiLdBaseRepository;

import java.util.Optional;

/**
 * Wrapper exception for everything that might go wrong when using the {@link NgsiLdBaseRepository}
 */
public class NgsiLdRepositoryException extends RuntimeException {

	@Getter
	private final Optional<Throwable> optionalCause;


	public NgsiLdRepositoryException(String message,  Optional<Throwable> cause) {
		super(message);
		optionalCause = cause;
	}
}
