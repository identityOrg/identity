package net.prasenjit.identity.controller.client;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.api.client.CreateClientRequest;
import net.prasenjit.identity.model.api.client.SearchClientRequest;
import net.prasenjit.identity.model.api.client.StatusClientRequest;
import net.prasenjit.identity.model.api.client.UpdateClientRequest;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.service.ClientService;
import org.springframework.data.domain.Example;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@SwaggerDocumented
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
        client.setRedirectUri(request.getRedirectUri());

        Example<Client> clientExample = Example.of(client);
        return clientRepository.findAll(clientExample);
    }

    @Override
    @GetMapping(value = "{clientId}")
    public Client findClient(@PathVariable(value = "clientId") String clientId) {
        Optional<Client> clientOptional = clientRepository.findById(clientId);
        if (clientOptional.isPresent()) {
            return clientOptional.get();
        } else {
            throw new ItemNotFoundException("Client not found");
        }
    }

    @Override
    @PutMapping(value = "{clientId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Client update(@PathVariable(value = "clientId") String clientId, @RequestBody UpdateClientRequest request) {
        request.setClientId(clientId);
        return clientService.updateClient(request);
    }

    @Override
    @ResponseStatus(code = HttpStatus.CREATED)
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public Client create(@RequestBody CreateClientRequest request) {
        return clientService.createClient(request);
    }

    @Override
    @PostMapping(value = "{clientId}/status", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Client status(@PathVariable(value = "clientId") String clientId, @RequestBody StatusClientRequest request) {
        return clientService.changeStatus(clientId, request.getStatus());
    }

    @Override
    @PostMapping(value = "{clientId}/secret", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Client secret(@PathVariable(value = "clientId") String clientId) {
        return clientService.resetSecret(clientId);
    }
}
