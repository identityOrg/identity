package net.prasenjit.identity.model.api.client;

import net.minidev.json.JSONObject;
import net.prasenjit.identity.entity.client.Client;

public class ClientDTO extends Client {
    public ClientDTO(Client client) {
        setAccessTokenValidity(client.getAccessTokenValidity());
        setClientName(client.getClientName());
        setRefreshTokenValidity(client.getRefreshTokenValidity());
        setStatus(client.getStatus());
        setClientId(client.getClientId());
        setCreationDate(client.getCreationDate());
        setMetadata(client.getMetadata());
        setExpiryDate(client.getExpiryDate());
    }

    public JSONObject getClientMetadata() {
        return getMetadata().toJSONObject();
    }
}
