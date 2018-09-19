package net.prasenjit.identity.service;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.stream.Collectors;

public final class ValidationUtils {

    @SuppressWarnings("unchecked")
    public static <T> T extractPrincipal(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (Profile.class.isInstance(principal)) {
                return (T) principal;
            }
        }
        return null;
    }

    public static Scope filterScopeToMap(String approved, Scope requestedScope, ConsentModel authorizationModel) {
        if (!StringUtils.hasText(approved)) {
            return new Scope();
        }
        Scope approvedScopes = Scope.parse(approved);
        if (requestedScope == null || requestedScope.isEmpty()) {
            authorizationModel.setFilteredScopes(approvedScopes.toStringList().stream()
                    .collect(Collectors.toMap(s -> s, s -> Boolean.TRUE)));
            return approvedScopes;
        }
        Scope filteredScopes = new Scope();
        for (String r : requestedScope.toStringList()) {
            if (approvedScopes.contains(r)) {
                authorizationModel.getFilteredScopes().put(r, Boolean.TRUE);
                filteredScopes.add(r);
            }
        }
        return filteredScopes;
    }

    public static boolean invalidGrant(AuthorizationRequest request, Client client) {
        // Grant validation start
        OIDCClientMetadata metadata = client.getMetadata();
        if (request.getResponseType().impliesCodeFlow()) {
            return !metadata.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE);
        }
        if (request.getResponseType().impliesImplicitFlow()) {
            return !metadata.getGrantTypes().contains(GrantType.IMPLICIT);
        }
        if (request.getResponseType().impliesHybridFlow()) {
            return !(metadata.getGrantTypes().contains(GrantType.IMPLICIT)
                    && metadata.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE));
        }
        // Grant validation end
        return false;
    }

    public static Scope filterScope(String approved, Scope requestedScope) {
        if (!StringUtils.hasText(approved)) {
            return new Scope();
        }
        Scope approvedScopes = Scope.parse(approved);
        if (requestedScope == null || requestedScope.isEmpty()) {
            return approvedScopes;
        }
        Scope filteredScopes = new Scope();
        for (String r : requestedScope.toStringList()) {
            if (approvedScopes.contains(r)) {
                filteredScopes.add(r);
            }
        }
        return filteredScopes;
    }

    public static Date convertToDate(LocalDateTime tdt) {
        if (tdt == null) {
            return null;
        }
        return Date.from(tdt.atZone(ZoneId.systemDefault()).toInstant());
    }

    public static LocalDateTime convertToLocalDateTime(Date date) {
        if (date == null) {
            return null;
        }
        return Instant.ofEpochMilli(date.getTime()).atZone(ZoneId.systemDefault()).toLocalDateTime();
    }
}
