package net.prasenjit.identity.service;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.Scope;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.ConsentModel;
import net.prasenjit.identity.model.Profile;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

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
        net.prasenjit.identity.security.GrantType[] approvedGrants = client.getApprovedGrants();
        if (request.getResponseType().impliesCodeFlow()) {
            if (!ArrayUtils.contains(approvedGrants, net.prasenjit.identity.security.GrantType.IMPLICIT)) {
                return true;
            }
        }
        if (request.getResponseType().impliesImplicitFlow()) {
            if (!ArrayUtils.contains(approvedGrants, net.prasenjit.identity.security.GrantType.AUTHORIZATION_CODE)) {
                return true;
            }
        }
        if (request.getResponseType().impliesHybridFlow()) {
            if (!ArrayUtils.contains(approvedGrants, net.prasenjit.identity.security.GrantType.AUTHORIZATION_CODE)) {
                return true;
            }
            if (!ArrayUtils.contains(approvedGrants, net.prasenjit.identity.security.GrantType.IMPLICIT)) {
                return true;
            }
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
}
