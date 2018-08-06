package net.prasenjit.identity.entity.client;

import lombok.Data;

import java.net.URL;

@Data
public class URIInfoContainer {
    private URL logoUri;
    private URL clientUri;
    private URL policyUri;
    private URL tosUri;
}
