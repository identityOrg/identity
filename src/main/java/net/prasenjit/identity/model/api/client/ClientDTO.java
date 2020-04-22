package net.prasenjit.identity.model.api.client;

import net.minidev.json.JSONObject;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.service.ClientService;

public class ClientDTO extends Client {
    public ClientDTO(Client client) {
        setStatus(client.getStatus());
        setClientId(client.getClientId());
        setCreationDate(client.getCreationDate());
        setMetadata(client.getMetadata());
        setExpiryDate(client.getExpiryDate());
        getMetadata().setName(client.getClientName());
        getMetadata().setCustomField(ClientService.ACCESS_TOKEN_VALIDITY_MINUTE,
                client.getAccessTokenValidity().toMinutes());
        getMetadata().setCustomField(ClientService.REFRESH_TOKEN_VALIDITY_MINUTE,
                client.getRefreshTokenValidity().toMinutes());
    }

    public JSONObject getClientMetadata() {
        return getMetadata().toJSONObject();
    }
}
