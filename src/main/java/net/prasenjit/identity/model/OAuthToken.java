package net.prasenjit.identity.model;

import lombok.Data;

import java.util.Date;

@Data
public class OAuthToken {
    private String accessToken;
    private String tokenType;
    private String refreshToken;
    private int expiresIn;
}
