package net.prasenjit.identity.model.api.client.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import net.prasenjit.identity.model.api.client.UpdateClientRequest;

import java.io.IOException;

public class UpdateClientRequestDeserializer extends StdDeserializer<UpdateClientRequest> {

    public UpdateClientRequestDeserializer() {
        this(null);
    }

    protected UpdateClientRequestDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public UpdateClientRequest deserialize(JsonParser parser, DeserializationContext context) throws IOException, JsonProcessingException {
        UpdateClientRequest updateClientRequest = null;
        if (parser.currentToken()== JsonToken.START_OBJECT) {
            updateClientRequest = new UpdateClientRequest();
            for (int i = 0; i<3;i++) {
                String fieldName = parser.nextFieldName();
                if ("clientId".equals(fieldName)) {
                    updateClientRequest.setClientId(parser.nextTextValue());
                } else if ("expiryDate".equals(fieldName)){
                    System.out.println(parser.nextTextValue());
                } else if ("clientMetadata".equals(fieldName)){
                    System.out.println(parser.getValueAsString());
                }
            }
        }

        return updateClientRequest;
    }
}
