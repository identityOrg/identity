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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.api.client.*;

import java.util.List;

@Tag(name = "client", description = "API's for client related operations")
public interface ClientApi {

    @Operation(summary = "Search Client", description = "Search a client with any client attribute")
    List<Client> searchClient(SearchClientRequest request);

    @Operation(summary = "Find Client", description = "Find a client with clientId")
    Client findClient(String clientId);

    @Operation(summary = "Update Client", description = "Update a client attributes")
    Client update(String clientId, UpdateClientRequest request);

    @Operation(summary = "Create Client", description = "Create a client, client is created is disabled state.")
    Client create(CreateClientRequest request);

    @Operation(summary = "Change Status", description = "Change client status.")
    Client status(String clientId, StatusClientRequest request);

    @Operation(summary = "Reset Secret", description = "Reset client secret.")
    Client secret(String clientId);

    @Operation(summary = "Get Secret", description = "Get client secret.")
    ClientSecretResponse getSecret(String clientId);
}
