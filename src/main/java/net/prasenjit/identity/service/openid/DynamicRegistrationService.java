/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.identity.service.openid;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.*;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.events.CreateEvent;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.service.ClientService;
import net.prasenjit.identity.service.ValidationUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class DynamicRegistrationService {

    private final IdentityProperties identityProperties;
    private final ClientRepository clientRepository;
    private final MetadataService metadataService;
    private final ApplicationEventPublisher eventPublisher;

    private TextEncryptor textEncryptor;

    @Transactional
    public ClientRegistrationResponse registerClient(OIDCClientRegistrationRequest request) {
        OIDCClientMetadata metadata = request.getOIDCClientMetadata();
        metadata.applyDefaults();

        ClientRegistrationResponse errorResponse = validateClientMetadata(metadata);
        if (errorResponse != null) {
            return errorResponse;
        }

        Client client = new Client();
        client.setClientName(metadata.getName());
        client.setMetadata(metadata);
        client.setStatus(Status.ACTIVE);
        retrieveCustomClientAttributes(metadata, client);

        client.setCreationDate(LocalDateTime.now());

        client.setClientId(generateUniqueClientId());

        String clientSecret = RandomStringUtils.randomAlphanumeric(identityProperties.getClientSecretLength());
        client.setClientSecret(textEncryptor.encrypt(clientSecret));

        CreateEvent csEvent = new CreateEvent(this, ResourceType.CLIENT, client.getClientId());
        eventPublisher.publishEvent(csEvent);
        clientRepository.saveAndFlush(client);

        return generateClientInfoResponse(client, metadata, true);
    }

    @Transactional
    public ClientRegistrationResponse updateClient(String id, OIDCClientUpdateRequest request) {
        ClientID clientID = request.getClientID();
        Base64URL clientIdb64 = new Base64URL(id);
        if (!clientID.getValue().equals(clientIdb64.decodeToString())) {
            ErrorObject error = new ErrorObject("invalid_client", "Client ID did not match", 401);
            return new ClientRegistrationErrorResponse(error);
        }
        Optional<Client> clientOptional = clientRepository.findById(clientIdb64.decodeToString());
        if (clientOptional.isPresent()) {
            OIDCClientMetadata clientMetadata = request.getOIDCClientMetadata();
            ClientRegistrationResponse errorResponse = validateClientMetadata(clientMetadata);
            if (errorResponse != null) {
                return errorResponse;
            }

            Client client = clientOptional.get();
            Secret clientSecret = request.getClientSecret();
            if (clientSecret != null && StringUtils.hasText(client.getClientSecret())) {
                if (textEncryptor.decrypt(client.getClientSecret()).equals(clientSecret.getValue())) {
                    String secret = RandomStringUtils.randomAlphanumeric(identityProperties.getClientSecretLength());
                    client.setClientSecret(textEncryptor.encrypt(secret));
                } else {
                    ErrorObject error = new ErrorObject("invalid_client", "Client secret did not match", 401);
                    return new ClientRegistrationErrorResponse(error);
                }
            }

            retrieveCustomClientAttributes(clientMetadata, client);

            client.setMetadata(clientMetadata);

            return generateClientInfoResponse(client, clientMetadata, false);
        } else {
            ErrorObject error = new ErrorObject("invalid_client", "Registration uri is invalid", 401);
            return new ClientRegistrationErrorResponse(error);
        }
    }

    @Transactional(readOnly = true)
    public ClientRegistrationResponse readClient(String id, ClientReadRequest request) {
        Base64URL clientIdb64 = new Base64URL(id);
        Optional<Client> clientOptional = clientRepository.findById(clientIdb64.decodeToString());
        if (clientOptional.isPresent()) {
            Client client = clientOptional.get();
            OIDCClientMetadata metadata = client.getMetadata();
            return generateClientInfoResponse(client, metadata, false);
        } else {
            ErrorObject error = new ErrorObject("invalid_uri", "Registration uri is invalid", 404);
            return new ClientRegistrationErrorResponse(error);
        }
    }

    @Transactional
    public int deleteClient(String id, ClientDeleteRequest request) {
        Base64URL clientIdb64 = new Base64URL(id);
        Optional<Client> clientOptional = clientRepository.findById(clientIdb64.decodeToString());
        if (clientOptional.isPresent()) {
            clientRepository.delete(clientOptional.get());
            return 200;
        } else {
            return 401;
        }
    }

    private ClientRegistrationResponse generateClientInfoResponse(Client client, OIDCClientMetadata clientMetadata, boolean newClient) {
        populateCustomClientAttributes(client, clientMetadata);
        ClientID clientId = new ClientID(client.getClientId());
        Date issueDate = ValidationUtils.convertToDate(client.getCreationDate());
        Secret secret = new Secret(textEncryptor.decrypt(client.getClientSecret()));
        URI registrationUri = metadataService.findClientRegistrationURI(client.getClientId());
        OIDCClientInformation clientInfo = new OIDCClientInformation(clientId, issueDate, clientMetadata, secret,
                registrationUri, null);
        return new OIDCClientInformationResponse(clientInfo, newClient);
    }

    public void retrieveCustomClientAttributes(OIDCClientMetadata clientMetadata, Client client) {

        JSONObject customParameters = clientMetadata.getCustomFields();
        Duration duration = null;
        try {
            long validity = JSONObjectUtils.getLong(customParameters, ClientService.ACCESS_TOKEN_VALIDITY_MINUTE);
            if (validity > 0) {
                duration = Duration.ofMinutes(validity);
            }
        } catch (ParseException ignored) {
            log.debug("Value of {} is not recognized, using default", ClientService.ACCESS_TOKEN_VALIDITY_MINUTE);
        }
        if (duration == null) {
            duration = Duration.ofMinutes(identityProperties.getCodeProperty().getAccessTokenValidityMinute());
            clientMetadata.setCustomField(ClientService.ACCESS_TOKEN_VALIDITY_MINUTE, duration.toMinutes());
        }
        client.setAccessTokenValidity(duration);

        duration = null;
        try {
            long validity = JSONObjectUtils.getLong(customParameters, ClientService.REFRESH_TOKEN_VALIDITY_MINUTE);
            if (validity > 0) {
                duration = Duration.ofMinutes(validity);
            }
        } catch (ParseException e) {
            log.debug("Value of {} is not recognized, using default", ClientService.REFRESH_TOKEN_VALIDITY_MINUTE);
        }
        if (duration == null) {
            duration = Duration.ofMinutes(identityProperties.getCodeProperty().getRefreshTokenValidity());
            clientMetadata.setCustomField(ClientService.REFRESH_TOKEN_VALIDITY_MINUTE, duration.toMinutes());
        }
        client.setRefreshTokenValidity(duration);
    }

    public void populateCustomClientAttributes(Client client, OIDCClientMetadata clientMetadata) {
        Duration tokenValidity = client.getAccessTokenValidity();
        clientMetadata.setCustomField(ClientService.ACCESS_TOKEN_VALIDITY_MINUTE, tokenValidity.toMinutes());
        tokenValidity = client.getRefreshTokenValidity();
        clientMetadata.setCustomField(ClientService.REFRESH_TOKEN_VALIDITY_MINUTE, tokenValidity.toMinutes());
        LocalDateTime expiryDate = client.getExpiryDate();
        clientMetadata.setCustomField(ClientService.EXPIRY_DATE, expiryDate);
        clientMetadata.setCustomField(ClientService.STATUS, client.getStatus());
    }

    public String generateUniqueClientId() {
        Optional<Client> optional;
        String clientId;
        do {
            clientId = RandomStringUtils.randomAlphanumeric(identityProperties.getClientIdLength());
            optional = clientRepository.findById(clientId);
        } while (optional.isPresent());
        return clientId;
    }

    @SneakyThrows
    public ClientRegistrationResponse validateClientMetadata(OIDCClientMetadata clientMetadata) {
        OIDCProviderMetadata serverMetadata = metadataService.findOIDCConfiguration();

        // Grant validation
        Set<GrantType> grantTypes = clientMetadata.getGrantTypes();
        if (CollectionUtils.isEmpty(grantTypes)) {
            clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
        } else {
            if (grantTypes.stream().anyMatch(gt -> !serverMetadata.getGrantTypes().contains(gt))) {
                return new ClientRegistrationErrorResponse(
                        RegistrationError.INVALID_CLIENT_METADATA.appendDescription(": Unsupported Grant"));
            }
        }

        // Req Obj EncryptionMethod validation
        EncryptionMethod encMethod = clientMetadata.getRequestObjectJWEEnc();
        if (encMethod != null && !serverMetadata.getRequestObjectJWEEncs().contains(encMethod)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported request object encryption method"));
        }

        // Req Obj EncryptionMethod validation
        JWEAlgorithm encAlgo = clientMetadata.getRequestObjectJWEAlg();
        if (encAlgo != null && !serverMetadata.getRequestObjectJWEAlgs().contains(encAlgo)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported request object encryption algorithm"));
        }

        // Req Obj EncryptionMethod validation
        JWSAlgorithm sigAlgo = clientMetadata.getRequestObjectJWSAlg();
        if (sigAlgo != null && !serverMetadata.getRequestObjectJWSAlgs().contains(sigAlgo)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported request object signing algorithm"));
        }

        // IDToken EncryptionMethod validation
        encMethod = clientMetadata.getIDTokenJWEEnc();
        if (encMethod != null && !serverMetadata.getIDTokenJWEEncs().contains(encMethod)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported id token encryption method"));
        }

        // IDToken EncryptionMethod validation
        encAlgo = clientMetadata.getIDTokenJWEAlg();
        if (encAlgo != null && !serverMetadata.getIDTokenJWEAlgs().contains(encAlgo)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported id token encryption algorithm"));
        }

        // IDToken EncryptionMethod validation
        sigAlgo = clientMetadata.getIDTokenJWSAlg();
        if (sigAlgo == null) {
            clientMetadata.setIDTokenJWSAlg(JWSAlgorithm.RS256);
        } else if (!serverMetadata.getIDTokenJWSAlgs().contains(sigAlgo)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported id token signing algorithm"));
        }

        // IDToken EncryptionMethod validation
        encMethod = clientMetadata.getUserInfoJWEEnc();
        if (encMethod != null && !serverMetadata.getUserInfoJWEEncs().contains(encMethod)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported user info encryption method"));
        }

        // IDToken EncryptionMethod validation
        encAlgo = clientMetadata.getUserInfoJWEAlg();
        if (encAlgo != null && !serverMetadata.getUserInfoJWEAlgs().contains(encAlgo)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported user info encryption algorithm"));
        }

        // IDToken EncryptionMethod validation
        sigAlgo = clientMetadata.getUserInfoJWSAlg();
        if (sigAlgo != null && !serverMetadata.getUserInfoJWSAlgs().contains(sigAlgo)) {
            return new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA
                    .appendDescription(": Unsupported user info signing algorithm"));
        }

        // Scope validation
        Scope scope = clientMetadata.getScope();
        if (CollectionUtils.isEmpty(scope)) {
            clientMetadata.setScope(Scope.parse("openid"));
        } else {
            List<String> collect = scope.stream()
                    .filter(s -> serverMetadata.getScopes().contains(s.getValue()))
                    .map(Identifier::getValue)
                    .collect(Collectors.toList());
            scope = Scope.parse(collect);
            clientMetadata.setScope(scope);
        }

        // Response type validation
        Set<ResponseType> responseTypes = clientMetadata.getResponseTypes();
        if (CollectionUtils.isEmpty(responseTypes)) {
            clientMetadata.setResponseTypes(Collections.singleton(ResponseType.parse("code")));
        } else {
            if (responseTypes.stream().anyMatch(rt -> !serverMetadata.getResponseTypes().contains(rt))) {
                return new ClientRegistrationErrorResponse(
                        RegistrationError.INVALID_CLIENT_METADATA.appendDescription(": Unsupported Response Type"));
            }
        }

        // Client authentication for Token EP type validation
        ClientAuthenticationMethod tokenEndpointAuthMethod = clientMetadata.getTokenEndpointAuthMethod();
        if (tokenEndpointAuthMethod == null) {
            clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        } else if (!(serverMetadata.getTokenEndpointAuthMethods().contains(tokenEndpointAuthMethod))) {
            return new ClientRegistrationErrorResponse(
                    RegistrationError.INVALID_CLIENT_METADATA
                            .appendDescription(": Unsupported Client authentication method"));
        }
        JWSAlgorithm tokenEndpointAuthJWSAlg = clientMetadata.getTokenEndpointAuthJWSAlg();
        if (tokenEndpointAuthJWSAlg != null
                && !(serverMetadata.getTokenEndpointJWSAlgs().contains(tokenEndpointAuthJWSAlg))) {
            return new ClientRegistrationErrorResponse(
                    RegistrationError.INVALID_CLIENT_METADATA
                            .appendDescription(": Unsupported Client authentication signing algorithm"));
        }

        // Subject type validation
        SubjectType subjectType = clientMetadata.getSubjectType();
        if (subjectType == null) {
            clientMetadata.setSubjectType(SubjectType.PUBLIC);
        } else if (subjectType == SubjectType.PAIRWISE) {
            return new ClientRegistrationErrorResponse(
                    RegistrationError.INVALID_CLIENT_METADATA.appendDescription(": Unsupported Subject Type"));
        }
        return null;
    }

    @Autowired
    @Qualifier("client-password")
    public void setTextEncryptor(TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }
}
