package org.fiware.iam.tir.auth;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.core.convert.value.ConvertibleValues;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.ContextAuthenticationMapper;
import io.micronaut.security.ldap.DefaultContextAuthenticationMapper;
import jakarta.inject.Singleton;
import lombok.extern.slf4j.Slf4j;

import java.util.Set;

@Slf4j
@Singleton
@Replaces(DefaultContextAuthenticationMapper.class)
public class MyContextAuthenticationMapper implements ContextAuthenticationMapper {
    @Override
    public AuthenticationResponse map(ConvertibleValues<Object> attributes, String username, Set<String> groups) {
        log.debug("Beka my context mapper");
        log.debug(username);
        log.debug(attributes.asProperties().toString());
        log.debug(attributes.asProperties().elements().toString());
        log.debug(groups.toString());
        return AuthenticationResponse.success(username, groups);
    }
}
