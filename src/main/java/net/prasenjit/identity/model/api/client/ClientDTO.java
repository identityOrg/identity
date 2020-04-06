package net.prasenjit.identity.model.api.client;

import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import net.prasenjit.identity.entity.client.Client;

import java.text.ParseException;

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

    public JSONObject getClientMetadata() throws ParseException {
        return JSONObjectUtils.parse(getClientMetadata().toJSONString());
    }
}
