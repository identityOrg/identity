package net.prasenjit.identity.properties;

import lombok.Data;

import java.util.List;

@Data
public class ServerMetadata {
    private String issuer;
    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String[] tokenEndpointAuthMethodsSupported;
    private String[] tokenEndpointAuthSigningAlgValuesSupported;
    private String userinfoEndpoint;
    private String checkSessionIframe;
    private String endSessionEndpoint;
    private String jwksURI;
    private String registrationEndpoint;
    private List<String> scopesSupported;
    private String[] responseTypesSupported;
    private String[] grantTypesSupported;
    private String[] acrValuesSupported;
    private String[] subjectTypesSupported;
    private String[] userinfoSigningAlgValuesSupported;
    private String[] userinfoEncryptionAlgValuesSupported;
    private String[] userinfoEncryptionEncValuesSupported;
    private String[] idTokenSigningAlgValuesSupported;
    private String[] idTokenEncryptionAlgValuesSupported;
    private String[] idTokenEncryptionEncValuesSupported;
    private String[] requestObjectSigningAlgValuesSupported;
    private String[] displayValuesSupported;
    private String[] claimTypesSupported;
    private String[] claimsSupported;
    private boolean claimsParameterSupported;
    private boolean requireRequestURIRegistration;
    private String serviceDocumentation;
    private String[] uiLocalesSupported;
}
