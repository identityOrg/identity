package net.prasenjit.identity.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.User;

import java.util.Map;

@Data
@NoArgsConstructor
public class AuthorizationModel {
    private boolean valid;
    private Client client;
    private User user;
    private String responseType;
    private String state;
    private String errorCode;
    private String errorDescription;
    private String redirectUri;
    private Map<String, Boolean> filteredScopes;
    private AccessToken accessToken;
    private AuthorizationCode authorizationCode;

    public boolean isImplicitResponse() {
        return "token".equals(responseType);
    }

    public boolean isAuthorizationCodeResponse() {
        return "code".equals(responseType);
    }
}
