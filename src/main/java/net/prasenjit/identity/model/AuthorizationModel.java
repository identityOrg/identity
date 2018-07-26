package net.prasenjit.identity.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.Client;

import java.util.HashMap;
import java.util.Map;

@Data
@NoArgsConstructor
public class AuthorizationModel {
    private boolean openid = false;
    private boolean valid = false;
    private Client client;
    private Profile profile;
    private String responseType;
    private String state;
    private String errorCode;
    private String errorDescription;
    private String redirectUri;
    private Map<String, Boolean> filteredScopes = new HashMap<>();
    private AccessToken accessToken;
    private AuthorizationCode authorizationCode;
    private boolean loginRequired;
    private boolean consentRequired;
    private String nonce;
}
