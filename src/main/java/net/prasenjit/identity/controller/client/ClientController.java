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

package net.prasenjit.identity.controller.client;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.api.client.*;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.service.ClientService;
import org.springframework.data.domain.Example;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping(value = "api/client", produces = MediaType.APPLICATION_JSON_VALUE)
public class ClientController implements ClientApi {

    private final ClientRepository clientRepository;
    private final ClientService clientService;

    @Override
    @GetMapping
    public List<Client> searchClient(@ModelAttribute SearchClientRequest request) {
        Client client = new Client();
        client.setClientName(request.getClientName());
        client.setStatus(request.getStatus());

        Example<Client> clientExample = Example.of(client);
        return clientRepository.findAll(clientExample);
    }

    @Override
    @GetMapping(value = "{clientId}")
    public ClientDTO findClient(@PathVariable(value = "clientId") String clientId) {
        Optional<Client> clientOptional = clientRepository.findById(clientId);
        if (clientOptional.isPresent()) {
            return new ClientDTO(clientOptional.get());
        } else {
            throw new ItemNotFoundException("Client not found");
        }
    }

    @Override
    @PutMapping(value = "{clientId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ClientDTO update(@PathVariable(value = "clientId") String clientId,
                         @RequestBody @Valid UpdateClientRequest request) {
        request.setClientId(clientId);
        return new ClientDTO(clientService.updateClient(request));
    }

    @Override
    @ResponseStatus(code = HttpStatus.CREATED)
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ClientDTO create(@RequestBody @Valid CreateClientRequest request) {
        return new ClientDTO(clientService.createClient(request));
    }

    @Override
    @PostMapping(value = "{clientId}/status", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ClientDTO status(@PathVariable(value = "clientId") String clientId,
                         @RequestBody @Valid StatusClientRequest request) {
        return new ClientDTO(clientService.changeStatus(clientId, request.getStatus()));
    }

    @Override
    @PostMapping(value = "{clientId}/secret")
    public ClientDTO secret(@PathVariable(value = "clientId") String clientId) {
        return new ClientDTO(clientService.resetSecret(clientId));
    }

    @Override
    @GetMapping(value = "{clientId}/secret")
    public ClientSecretResponse getSecret(@PathVariable(value = "clientId") String clientId) {
        return clientService.displayClientSecret(clientId);
    }
}
