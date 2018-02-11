package net.prasenjit.identity.controller.client;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.api.CreateClientRequest;
import net.prasenjit.identity.model.api.SearchClientRequest;
import net.prasenjit.identity.model.api.UpdateClientRequest;
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
@RequestMapping(value = "api/client")
public class ClientController implements ClientApi {

    private final ClientRepository clientRepository;
    private final ClientService clientService;

    @Override
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Client> searchClient(@ModelAttribute SearchClientRequest request) {
        Client client = new Client();
        client.setClientName(request.getClientName());
        client.setStatus(request.getStatus());
        client.setRedirectUri(request.getRedirectUri());

        Example<Client> clientExample = Example.of(client);
        return clientRepository.findAll(clientExample);
    }

    @Override
    @GetMapping(value = "{clientId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Client findClient(@PathVariable(value = "clientId") String clientId) {
        Optional<Client> clientOptional = clientRepository.findById(clientId);
        if (clientOptional.isPresent()) {
            return clientOptional.get();
        } else {
            throw new ItemNotFoundException("Client not found");
        }
    }

    @Override
    @PutMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public Client update(@RequestBody UpdateClientRequest request) {
        return clientService.updateClient(request);
    }

    @Override
    @ResponseStatus(code = HttpStatus.CREATED)
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public Client create(@RequestBody CreateClientRequest request) {
        return clientService.createClient(request);
    }
}
