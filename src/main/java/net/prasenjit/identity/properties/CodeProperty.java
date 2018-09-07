package net.prasenjit.identity.properties;

import lombok.Data;

@Data
public class CodeProperty {
    private int authorizationCodeLength = 8;
}
