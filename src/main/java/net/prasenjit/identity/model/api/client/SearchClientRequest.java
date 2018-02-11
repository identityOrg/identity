package net.prasenjit.identity.model.api.client;

import lombok.Data;
import net.prasenjit.identity.entity.Status;

@Data
public class SearchClientRequest {
    private String clientId;
    private String clientName;
    private Status status;
    private String approvedScopes;
    private String redirectUri;
}
