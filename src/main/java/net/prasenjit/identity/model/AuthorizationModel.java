package net.prasenjit.identity.model;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.User;

import java.util.Map;

@Data
@NoArgsConstructor
public class AuthorizationModel {
    private boolean valid;
    private Client client;
    private User user;
    private String state;
    private String errorCode;
    private String authorizationCode;
    private String errorDescription;
    private String redirectUri;
    private String scope;
    private Map<String, Boolean> filteredScopes;
}
