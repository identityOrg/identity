package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.InvalidRequestException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.exception.OperationIgnoredException;
import net.prasenjit.identity.model.api.client.ClientSecretResponse;
import net.prasenjit.identity.model.api.client.CreateClientRequest;
import net.prasenjit.identity.model.api.client.UpdateClientRequest;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.ScopeRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ClientService implements UserDetailsService {

    private final ClientRepository clientRepository;
    private final ScopeRepository scopeRepository;

    @Autowired
    @Qualifier("client-password")
    public TextEncryptor textEncryptor;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<Client> client = clientRepository.findById(s);
        if (client.isPresent()) {
            return client.get();
        } else {
            throw new UsernameNotFoundException("client not found");
        }
    }

    @Transactional
    public Client createClient(CreateClientRequest request) {
        if (StringUtils.hasText(request.getClientId())) {
            Optional<Client> optionalClient = clientRepository.findById(request.getClientId());
            if (optionalClient.isPresent()) {
                throw new ConflictException("Client already exist.");
            }
        } else {
            Optional<Client> optional;
            do {
                request.setClientId(UUID.randomUUID().toString());
                optional = clientRepository.findById(request.getClientId());
            } while (optional.isPresent());
        }
        Client client = new Client();
        client.setStatus(Status.LOCKED);
        LocalDateTime now = LocalDateTime.now();
        client.setCreationDate(now);
        client.setClientSecret(RandomStringUtils.randomAlphanumeric(20)); // unknown password to create disabled user
        client.setRedirectUri(request.getRedirectUri().toString());
        client.setClientName(request.getClientName());
        client.setExpiryDate(request.getExpiryDate());
        client.setAccessTokenValidity(request.getAccessTokenValidity());
        client.setRefreshTokenValidity(request.getRefreshTokenValidity());
        client.setClientId(request.getClientId());
        client.setScopes(request.getScopes());

        return clientRepository.saveAndFlush(client);
    }

    @Transactional
    public Client updateClient(UpdateClientRequest request) {
        Optional<Client> optionalClient = clientRepository.findById(request.getClientId());
        if (!optionalClient.isPresent()) {
            throw new ItemNotFoundException("Client not found.");
        }
        Client savedClient = optionalClient.get();
        savedClient.setRedirectUri(request.getRedirectUri().toString());
        savedClient.setClientName(request.getClientName());
        savedClient.setRefreshTokenValidity(request.getRefreshTokenValidity());
        savedClient.setAccessTokenValidity(request.getAccessTokenValidity());
        savedClient.setScopes(request.getScopes());
        savedClient.setExpiryDate(request.getExpiryDate());

        return savedClient;
    }

    @Transactional
    public Client changeStatus(String clientId, Status status) {
        Optional<Client> optionalClient = clientRepository.findById(clientId);
        if (!optionalClient.isPresent()) {
            throw new ItemNotFoundException("Client not found.");
        } else if (optionalClient.get().getStatus() == status) {
            throw new OperationIgnoredException("Status not changed");
        } else {
            optionalClient.get().setStatus(status);
        }
        return optionalClient.get();
    }

    @Transactional
    public Client resetSecret(String clientId) {
        Optional<Client> optionalClient = clientRepository.findById(clientId);
        if (!optionalClient.isPresent()) {
            throw new ItemNotFoundException("Client not found.");
        } else {
            String encryptedClientId = textEncryptor.encrypt(RandomStringUtils.randomAlphanumeric(20));
            optionalClient.get().setClientSecret(encryptedClientId);
        }
        return optionalClient.get();
    }

    private void validateClientScope(String approvedScopes) {
        String[] scopes = StringUtils.delimitedListToStringArray(approvedScopes, " ");
        for (String scope : scopes) {
            if (!scopeRepository.findById(scope).isPresent()) {
                throw new InvalidRequestException("Invalid scope");
            }
        }
    }

    @Transactional(readOnly = true)
    public ClientSecretResponse displayClientSecret(String clientId) {
        Optional<Client> clientOptional = clientRepository.findById(clientId);
        if (clientOptional.isPresent()) {
            Client client = clientOptional.get();
            ClientSecretResponse resp = new ClientSecretResponse();
            resp.setClientSecret(textEncryptor.decrypt(client.getClientSecret()));
            return resp;
        } else {
            throw new ItemNotFoundException("Client not found");
        }
    }
}
