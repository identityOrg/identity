package net.prasenjit.identity.model.openid.registration;

import lombok.Data;
import net.prasenjit.identity.model.openid.EncryptionAlgorithm;
import net.prasenjit.identity.model.openid.EncryptionEnc;
import net.prasenjit.identity.model.openid.SignatureAlgorithm;
import net.prasenjit.identity.security.GrantType;
import net.prasenjit.identity.security.ResponseType;
import net.prasenjit.identity.security.TokenEPAuthMethod;

import java.net.URL;

@Data
public class ClientRegistrationRequest {
    /**
     * REQUIRED. Array of Redirection URI values used by the Client. One of these registered Redirection URI
     * values MUST exactly match the redirect_uri parameter value used in each Authorization Request, with the
     * matching performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
     */
    private String[] redirect_uris;
    /**
     * OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type values that the Client is declaring
     * that it will restrict itself to using. If omitted, the default is that the Client will use only the
     * code Response Type.
     */
    private ResponseType[] response_types;
    /**
     * OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Types that the Client is declaring that it will
     * restrict itself to using. The Grant Type values used by OpenID Connect are:<br>
     * <b>authorization_code</b>: The Authorization Code Grant Type described in OAuth 2.0 Section 4.1.<br>
     * <b>implicit</b>: The Implicit Grant Type described in OAuth 2.0 Section 4.2.<br>
     * <b>refresh_token</b>: The Refresh Token Grant Type described in OAuth 2.0 Section 6.<br>
     * The following table lists the correspondence between response_type values that the Client will use and
     * grant_type values that MUST be included in the registered grant_types list:<br>
     * <ul>
     * <li>code: authorization_code</li>
     * <li>id_token: implicit</li>
     * <li>token id_token: implicit</li>
     * <li>code id_token: authorization_code, implicit</li>
     * <li>code token: authorization_code, implicit</li>
     * <li>code token id_token: authorization_code, implicit</li>
     * </ul><br>
     * If omitted, the default is that the Client will use only the authorization_code Grant Type.
     */
    private GrantType[] grant_types;
    /**
     * OPTIONAL. Kind of the application. The default, if omitted, is web. The defined values are native or web.
     * Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris;
     * they MUST NOT use localhost as the hostname. Native Clients MUST only register redirect_uris using custom
     * URI schemes or URLs using the http: scheme with localhost as the hostname. Authorization Servers MAY place
     * additional constraints on Native Clients. Authorization Servers MAY reject Redirection URI values using the
     * http scheme, other than the localhost case for Native Clients. The Authorization Server MUST verify that all
     * the registered redirect_uris conform to these constraints. This prevents sharing a Client ID across different
     * types of Clients.
     */
    private ApplicationType application_type = ApplicationType.WEB;
    /**
     * OPTIONAL. Array of e-mail addresses of people responsible for this Client. This might be used by some
     * providers to enable a Web user interface to modify the Client information.
     */
    private String[] contacts;
    /**
     * OPTIONAL. Name of the Client to be presented to the End-User. If desired, representation of this Claim in
     * different languages and scripts is represented as described in Section 2.1.
     */
    private String client_name;
    /**
     * OPTIONAL. URL that references a logo for the Client application. If present, the server SHOULD display this
     * image to the End-User during approval. The value of this field MUST point to a valid image file. If desired,
     * representation of this Claim in different languages and scripts is represented as described in Section 2.1.
     */
    private URL logo_uri;
    /**
     * OPTIONAL. URL of the home page of the Client. The value of this field MUST point to a valid Web page.
     * If present, the server SHOULD display this URL to the End-User in a followable fashion. If desired,
     * representation of this Claim in different languages and scripts is represented as described in Section 2.1.
     */
    private URL client_uri;
    /**
     * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the how the profile data
     * will be used. The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display
     * this URL to the End-User if it is given. If desired, representation of this Claim in different languages
     * and scripts is represented as described in Section 2.1.
     */
    private URL policy_uri;
    /**
     * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the Relying Party's terms
     * of service. The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display this
     * URL to the End-User if it is given. If desired, representation of this Claim in different languages and
     * scripts is represented as described in Section 2.1.
     */
    private URL tos_uri;
    /**
     * OPTIONAL. URL for the Client's JSON Web Key Set [JWK] document. If the Client signs requests to the Server,
     * it contains the signing key(s) the Server uses to validate signatures from the Client. The JWK Set MAY also
     * contain the Client's encryption keys(s), which are used by the Server to encrypt responses to the Client.
     * When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for
     * all keys in the referenced JWK Set to indicate each key's intended usage. Although some algorithms allow
     * the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure.
     * The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. When used, the bare key
     * values MUST still be present and MUST match those in the certificate.
     */
    private URL jwks_uri;
    /**
     * OPTIONAL. Client's JSON Web Key Set [JWK] document, passed by value. The semantics of the jwks parameter are
     * the same as the jwks_uri parameter, other than that the JWK Set is passed by value, rather than by reference.
     * This parameter is intended only to be used by Clients that, for some reason, are unable to use the jwks_uri
     * parameter, for instance, by native applications that might not have a location to host the contents of the
     * JWK Set. If a Client can use jwks_uri, it MUST NOT use jwks. One significant downside of jwks is that it
     * does not enable key rotation (which jwks_uri does, as described in Section 10 of OpenID Connect Core 1.0
     * [OpenID.Core]). The jwks_uri and jwks parameters MUST NOT be used together.
     */
    private String jwks;
    /**
     * OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client. The value none
     * MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that return no ID Token
     * from the Authorization Endpoint (such as when only using the Authorization Code Flow). The default, if omitted,
     * is RS256. The public key for validating the signature is provided by retrieving the JWK Set referenced by the
     * jwks_uri element from OpenID Connect Discovery 1.0 [OpenID.Discovery].
     */
    private SignatureAlgorithm id_token_signed_response_alg = SignatureAlgorithm.RS256;
    /**
     * OPTIONAL. JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If this is
     * requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT].
     * The default, if omitted, is that no encryption is performed.
     */
    private EncryptionAlgorithm id_token_encrypted_response_alg = EncryptionAlgorithm.RSA_OAEP;
    /**
     * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If
     * id_token_encrypted_response_alg is specified, the default for this value is A128CBC-HS256. When
     * id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
     */
    private EncryptionEnc id_token_encrypted_response_enc = EncryptionEnc.A128CBC_HS256;
    /**
     * OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the response
     * will be JWT [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo Response to
     * return the Claims as a UTF-8 encoded JSON object using the application/json content-type.
     */
    private SignatureAlgorithm userinfo_signed_response_alg = SignatureAlgorithm.RS256;
    /**
     * OPTIONAL. JWE [JWE] alg algorithm [JWA] REQUIRED for encrypting UserInfo Responses. If both signing and
     * encryption are requested, the response will be signed then encrypted, with the result being a Nested JWT,
     * as defined in [JWT]. The default, if omitted, is that no encryption is performed.
     */
    private EncryptionAlgorithm userinfo_encrypted_response_alg = EncryptionAlgorithm.RSA_OAEP;
    /**
     * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses.
     * If userinfo_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
     * When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided.
     */
    private EncryptionEnc userinfo_encrypted_response_enc = EncryptionEnc.A128CBC_HS256;
    /**
     * OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP.
     * All Request Objects from this Client MUST be rejected, if not signed with this algorithm. Request Objects are
     * described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST be used both when the
     * Request Object is passed by value (using the request parameter) and when it is passed by reference (using the
     * request_uri parameter). Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is
     * that any algorithm supported by the OP and the RP MAY be used.
     */
    private SignatureAlgorithm request_object_signing_alg = SignatureAlgorithm.RS256;
    /**
     * OPTIONAL. JWE [JWE] alg algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects
     * sent to the OP. This parameter SHOULD be included when symmetric encryption will be used, since this signals
     * to the OP that a client_secret value needs to be returned from which the symmetric key will be derived,
     * that might not otherwise be returned. The RP MAY still use other supported encryption algorithms or send
     * unencrypted Request Objects, even when this parameter is present. If both signing and encryption are requested,
     * the Request Object will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT].
     * The default, if omitted, is that the RP is not declaring whether it might encrypt any Request Objects.
     */
    private EncryptionAlgorithm request_object_encryption_alg = EncryptionAlgorithm.RSA_OAEP;
    /**
     * OPTIONAL. JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent
     * to the OP. If request_object_encryption_alg is specified, the default for this value is A128CBC-HS256.
     * When request_object_encryption_enc is included, request_object_encryption_alg MUST also be provided.
     */
    private EncryptionEnc request_object_encryption_enc = EncryptionEnc.A128CBC_HS256;
    /**
     * OPTIONAL. Requested Client Authentication method for the Token Endpoint. The options are client_secret_post,
     * client_secret_basic, client_secret_jwt, private_key_jwt, and none, as described in Section 9 of
     * OpenID Connect Core 1.0 [OpenID.Core]. Other authentication methods MAY be defined by extensions.
     * If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in
     * Section 2.3.1 of OAuth 2.0 [RFC6749].
     */
    private TokenEPAuthMethod token_endpoint_auth_method;
    /**
     * OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used to authenticate
     * the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods.
     * All Token Requests using these authentication methods from this Client MUST be rejected, if the JWT is
     * not signed with this algorithm. Servers SHOULD support RS256. The value none MUST NOT be used. The default,
     * if omitted, is that any algorithm supported by the OP and the RP MAY be used.
     */
    private SignatureAlgorithm token_endpoint_auth_signing_alg;
    /**
     * OPTIONAL. Default Maximum Authentication Age. Specifies that the End-User MUST be actively authenticated
     * if the End-User was authenticated longer ago than the specified number of seconds. The max_age request
     * parameter overrides this default value. If omitted, no default Maximum Authentication Age is specified.
     */
    private int default_max_age;
    /**
     * OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is REQUIRED. It is REQUIRED
     * when the value is true. (If this is false, the auth_time Claim can still be dynamically requested as an
     * individual Claim for the ID Token using the claims request parameter described in Section 5.5.1 of
     * OpenID Connect Core 1.0 [OpenID.Core].) If omitted, the default value is false.
     */
    private boolean require_auth_time;

}
