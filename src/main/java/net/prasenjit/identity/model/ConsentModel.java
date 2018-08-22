package net.prasenjit.identity.model;

import lombok.Data;
import net.prasenjit.identity.entity.client.Client;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@Data
public class ConsentModel {
    private Map<String, Boolean> filteredScopes = new HashMap<>();
    private Client client;
    private URI requestUri;
    private boolean openid = false;
    private boolean valid = false;
    private boolean consentSubmitted = false;
    private URI redirectUriUsed;
}
