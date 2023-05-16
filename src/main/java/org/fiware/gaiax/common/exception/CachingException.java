package org.fiware.gaiax.common.exception;

/**
 * Exception to be thrown in case cache-access fails for some reasons.
 */
public class CachingException extends RuntimeException {

	public CachingException(String message) {
		super(message);
	}

	public CachingException(String message, Throwable cause) {
		super(message, cause);
	}
}
