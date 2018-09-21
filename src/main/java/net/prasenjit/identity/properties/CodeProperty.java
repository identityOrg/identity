package net.prasenjit.identity.properties;

import lombok.Data;

@Data
public class CodeProperty {
    private int authorizationCodeLength = 8;
    private int accessTokenValidityMinute = 10;
    private int refreshTokenValidity = 60;
}
