package kz.sanscrit.auth.service;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;

        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        if (token.getAccount().getRoles().contains("demo-user-role")) {

            // use the credentials
            // and authenticate against the third-party system
            return token;
        } else {
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(
                KeycloakAuthenticationToken.class);
    }

}
