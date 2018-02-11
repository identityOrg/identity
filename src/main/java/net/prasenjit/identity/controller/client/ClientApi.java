package net.prasenjit.identity.controller.client;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.model.api.CreateClientRequest;
import net.prasenjit.identity.model.api.SearchClientRequest;
import net.prasenjit.identity.model.api.UpdateClientRequest;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@Api(value = "Client", tags = "client", description = "API's for client related operations")
public interface ClientApi {

    @ApiOperation(value = "Search Client", notes = "Search a client with any client attribute")
    List<Client> searchClient(@ModelAttribute SearchClientRequest request);

    @ApiOperation(value = "Find Client", notes = "Find a client with clientId")
    Client findClient(@PathVariable(value = "clientId") String clientId);

    @ApiOperation(value = "Update Client", notes = "Update a client attributes")
    Client update(@RequestBody UpdateClientRequest request);

    @ApiOperation(value = "Create Client", notes = "Create a client, client is created is disabled state.")
    Client create(@RequestBody CreateClientRequest request);
}
