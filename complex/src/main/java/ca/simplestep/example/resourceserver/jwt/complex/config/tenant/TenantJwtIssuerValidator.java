package ca.simplestep.example.resourceserver.jwt.complex.config.tenant;

import ca.simplestep.example.resourceserver.jwt.complex.config.ApplicationProperties;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TenantJwtIssuerValidator implements OAuth2TokenValidator<Jwt> {
    private final Map<String, JwtIssuerValidator> validators = new ConcurrentHashMap<>();
    private final ApplicationProperties applicationProperties;

    public TenantJwtIssuerValidator(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        return this.validators.computeIfAbsent(toTenant(token), this::fromTenant)
                .validate(token);
    }

    private String toTenant(Jwt jwt) {
        return jwt.getIssuer().toString();
    }

    private JwtIssuerValidator fromTenant(String tenant) {
        return this.applicationProperties.getIssuers().stream().filter(item -> Objects.equals(item, tenant))
                .map(JwtIssuerValidator::new)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("unknown tenant"));
    }
}
