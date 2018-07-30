package net.prasenjit.identity.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.Client;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Data
@NoArgsConstructor
public class AuthorizationModel {
    private boolean openid = false;
    private boolean valid = false;
    private Client client;
    private Profile profile;
    private LocalDateTime loginTime;
    private String responseType;
    private String state;
    private String errorCode;
    private String errorDescription;
    private String redirectUri;
    private Map<String, Boolean> filteredScopes = new HashMap<>();
    private AccessToken accessToken;
    private AuthorizationCode authorizationCode;
    private String idToken;
    private boolean loginRequired;
    private boolean consentRequired = true;
    private String nonce;

    public boolean requireCodeResponse() {
        return requireResponseType("code");
    }

    public boolean requireTokenResponse() {
        return requireResponseType("token");
    }

    public boolean requireIDTokenResponse() {
        return requireResponseType("id_token");
    }

    private boolean requireResponseType(String type) {
        String[] responseTypesRequested = StringUtils.delimitedListToStringArray(responseType, " ");
        Arrays.sort(responseTypesRequested);
        return Arrays.binarySearch(responseTypesRequested, type) > -1;
    }
}
