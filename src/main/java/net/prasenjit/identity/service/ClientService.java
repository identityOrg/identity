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

package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.events.ChangePasswordEvent;
import net.prasenjit.identity.events.ChangeStatusEvent;
import net.prasenjit.identity.events.CreateEvent;
import net.prasenjit.identity.events.UpdateEvent;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.exception.OperationIgnoredException;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.model.api.client.ClientSecretResponse;
import net.prasenjit.identity.model.api.client.CreateClientRequest;
import net.prasenjit.identity.model.api.client.UpdateClientRequest;
import net.prasenjit.identity.repository.ClientRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
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
    private final ApplicationEventPublisher eventPublisher;
    @Qualifier("client-password")
    private final TextEncryptor textEncryptor;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<Client> client = clientRepository.findById(s);
        if (client.isPresent()) {
            return Profile.create(client.get(), true);
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
        client.setClientSecret(RandomStringUtils.randomAlphanumeric(20)); // unknown password to create disabled client
        //client.setRedirectUri(request.getRedirectUri().toString());
        client.setClientName(request.getClientName());
        client.setExpiryDate(request.getExpiryDate());
        client.setAccessTokenValidity(request.getAccessTokenValidity());
        client.setRefreshTokenValidity(request.getRefreshTokenValidity());
        client.setClientId(request.getClientId());
        //client.setScopes(request.getScopes());

        CreateEvent csEvent = new CreateEvent(this,
                ResourceType.CLIENT, request.getClientId());
        eventPublisher.publishEvent(csEvent);

        return clientRepository.saveAndFlush(client);
    }

    @Transactional
    public Client updateClient(UpdateClientRequest request) {
        Optional<Client> optionalClient = clientRepository.findById(request.getClientId());
        if (!optionalClient.isPresent()) {
            throw new ItemNotFoundException("Client not found.");
        }
        Client savedClient = optionalClient.get();
        //savedClient.setRedirectUri(request.getRedirectUri().toString());
        savedClient.setClientName(request.getClientName());
        savedClient.setRefreshTokenValidity(request.getRefreshTokenValidity());
        savedClient.setAccessTokenValidity(request.getAccessTokenValidity());
        //savedClient.setScopes(request.getScopes());
        savedClient.setExpiryDate(request.getExpiryDate());

        UpdateEvent csEvent = new UpdateEvent(this,
                ResourceType.CLIENT, request.getClientId());
        eventPublisher.publishEvent(csEvent);

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

            ChangeStatusEvent csEvent = new ChangeStatusEvent(this,
                    ResourceType.CLIENT, clientId, status);
            eventPublisher.publishEvent(csEvent);
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

            ChangePasswordEvent cpEvent = new ChangePasswordEvent(this,
                    ResourceType.CLIENT, clientId);
            eventPublisher.publishEvent(cpEvent);
        }
        return optionalClient.get();
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
