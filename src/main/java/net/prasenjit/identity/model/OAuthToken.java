package net.prasenjit.identity.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class OAuthToken {
    private String accessToken;
    private String tokenType;
    private String refreshToken;
    private long expiresIn;
    private String scope;
}
