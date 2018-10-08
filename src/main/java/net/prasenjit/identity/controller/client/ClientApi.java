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

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.api.client.*;

import java.util.List;

@Api(value = "Client", tags = "client", description = "API's for client related operations")
public interface ClientApi {

    @ApiOperation(value = "Search Client", notes = "Search a client with any client attribute")
    List<Client> searchClient(SearchClientRequest request);

    @ApiOperation(value = "Find Client", notes = "Find a client with clientId")
    Client findClient(String clientId);

    @ApiOperation(value = "Update Client", notes = "Update a client attributes")
    Client update(String clientId, UpdateClientRequest request);

    @ApiOperation(value = "Create Client", notes = "Create a client, client is created is disabled state.")
    Client create(CreateClientRequest request);

    @ApiOperation(value = "Change Status", notes = "Change client status.")
    Client status(String clientId, StatusClientRequest request);

    @ApiOperation(value = "Reset Secret", notes = "Reset client secret.")
    Client secret(String clientId);

    @ApiOperation(value = "Get Secret", notes = "Get client secret.")
    ClientSecretResponse getSecret(String clientId);
}
