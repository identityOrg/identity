package net.prasenjit.identity.properties;

import lombok.Data;

@Data
public class SessionProperties {
    private String tableName = "T_SESSION";
    private int maxInactiveInterval = 300;
}
