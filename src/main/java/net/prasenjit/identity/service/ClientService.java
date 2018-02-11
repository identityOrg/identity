package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.InvalidRequestException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.exception.OperationIgnoredException;
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
    public Client createClient(Client client) {
        Optional<Client> optionalClient = clientRepository.findById(client.getUsername());
        if (optionalClient.isPresent()) {
            throw new ConflictException("Client already exist.");
        }
        client.setStatus(Status.LOCKED);
        LocalDateTime now = LocalDateTime.now();
        validateClientScope(client.getApprovedScopes());
        client.setCreationDate(now);
        client.setClientSecret(RandomStringUtils.randomAlphanumeric(20)); // unknown password to create disabled user
        return clientRepository.saveAndFlush(client);
    }

    @Transactional
    public Client updateClient(Client client) {
        Optional<Client> optionalClient = clientRepository.findById(client.getUsername());
        if (!optionalClient.isPresent()) {
            throw new ItemNotFoundException("Client not found.");
        }
        Client savedClient = optionalClient.get();
        savedClient.setRedirectUri(client.getRedirectUri());
        savedClient.setClientName(client.getClientName());
        savedClient.setRefreshTokenValidity(client.getRefreshTokenValidity());
        savedClient.setAccessTokenValidity(client.getAccessTokenValidity());
        savedClient.setApprovedScopes(client.getApprovedScopes());
        savedClient.setExpiryDate(client.getExpiryDate());
        validateClientScope(client.getApprovedScopes());
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

}
