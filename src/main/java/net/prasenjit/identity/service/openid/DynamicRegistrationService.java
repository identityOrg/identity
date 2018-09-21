package net.prasenjit.identity.service.openid;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientDeleteRequest;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.*;
import lombok.RequiredArgsConstructor;
import net.minidev.json.JSONObject;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.events.CreateEvent;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.service.ValidationUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class DynamicRegistrationService {

    private final IdentityProperties identityProperties;
    private final ClientRepository clientRepository;
    private final MetadataService metadataService;
    private final ApplicationEventPublisher eventPublisher;

    @Autowired
    @Qualifier("client-password")
    private TextEncryptor textEncryptor;

    @Transactional
    public ClientRegistrationResponse registerClient(OIDCClientRegistrationRequest request) throws ParseException {
        OIDCClientMetadata clientMetadata = request.getOIDCClientMetadata();
        clientMetadata.applyDefaults();
        Client client = new Client();
        client.setClientName(clientMetadata.getName());
        client.setMetadata(clientMetadata);
        client.setStatus(Status.ACTIVE);
        JSONObject customParameters = clientMetadata.getCustomFields();

        try {
            long validity = JSONObjectUtils.getLong(customParameters, "access_token_validity_minute");
            client.setAccessTokenValidity(Duration.ofSeconds(validity));
        } catch (ParseException e) {
            int tokenValidity = identityProperties.getCodeProperty().getAccessTokenValidityMinute();
            client.setAccessTokenValidity(Duration.ofMinutes(tokenValidity));
        }

        try {
            long validity = JSONObjectUtils.getLong(customParameters, "refresh_token_validity_minute");
            client.setRefreshTokenValidity(Duration.ofSeconds(validity));
        } catch (ParseException e) {
            int tokenValidity = identityProperties.getCodeProperty().getRefreshTokenValidity();
            client.setRefreshTokenValidity(Duration.ofMinutes(tokenValidity));
        }

        client.setCreationDate(LocalDateTime.now());

        Optional<Client> optional;
        do {
            client.setClientId(RandomStringUtils.randomAlphanumeric(10));
            optional = clientRepository.findById(client.getClientId());
        } while (optional.isPresent());

        String clientSecret = RandomStringUtils.randomAlphanumeric(identityProperties.getClientSecretLength());
        client.setClientSecret(textEncryptor.encrypt(clientSecret));

        CreateEvent csEvent = new CreateEvent(this, ResourceType.CLIENT, client.getClientId());
        eventPublisher.publishEvent(csEvent);
        clientRepository.saveAndFlush(client);

        //TODO client information validation to be done

        return generateClientInfoResponse(client, clientMetadata);
    }

    @Transactional
    public ClientRegistrationResponse updateClient(String id, OIDCClientUpdateRequest request) throws ParseException {
        Base64URL clientIdb64 = new Base64URL(id);
        Optional<Client> clientOptional = clientRepository.findById(clientIdb64.decodeToString());
        if (clientOptional.isPresent()) {
            Client client = clientOptional.get();
            OIDCClientMetadata clientMetadata = client.getMetadata();

            JSONObject customParameters = clientMetadata.getCustomFields();

            long validity = JSONObjectUtils.getLong(customParameters, "access_token_validity_minute");
            client.setAccessTokenValidity(Duration.ofSeconds(validity));

            validity = JSONObjectUtils.getLong(customParameters, "refresh_token_validity_minute");
            client.setRefreshTokenValidity(Duration.ofSeconds(validity));

            client.setMetadata(clientMetadata);
            client.setClientSecret(RandomStringUtils.randomAlphanumeric(identityProperties.getClientSecretLength()));

            return generateClientInfoResponse(client, clientMetadata);
        } else {
            ErrorObject error = new ErrorObject("invalid_uri", "Registration uri is invalid", 404);
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
            metadata.setCustomField("access_token_validity_minute", client.getAccessTokenValidity().toMinutes());
            metadata.setCustomField("refresh_token_validity_minute", client.getRefreshTokenValidity().toMinutes());

            return generateClientInfoResponse(client, metadata);
        } else {
            ErrorObject error = new ErrorObject("invalid_uri", "Registration uri is invalid", 404);
            return new ClientRegistrationErrorResponse(error);
        }
    }

    @Transactional
    public ClientRegistrationResponse deleteClient(String id, ClientDeleteRequest request) {
        Base64URL clientIdb64 = new Base64URL(id);
        Optional<Client> clientOptional = clientRepository.findById(clientIdb64.decodeToString());
        if (clientOptional.isPresent()) {
            return null;
        } else {
            ErrorObject error = new ErrorObject("invalid_uri", "Registration uri is invalid", 404);
            return new ClientRegistrationErrorResponse(error);
        }
    }

    private ClientRegistrationResponse generateClientInfoResponse(Client client, OIDCClientMetadata clientMetadata) {
        ClientID clientId = new ClientID(client.getClientId());
        Date issueDate = ValidationUtils.convertToDate(client.getCreationDate());
        Secret secret = new Secret(textEncryptor.decrypt(client.getClientSecret()));
        URI registrationUri = metadataService.findClientRegistrationURI(client.getClientId());
        OIDCClientInformation clientInfo = new OIDCClientInformation(clientId, issueDate, clientMetadata, secret,
                registrationUri, null);
        return new OIDCClientInformationResponse(clientInfo);
    }

}
