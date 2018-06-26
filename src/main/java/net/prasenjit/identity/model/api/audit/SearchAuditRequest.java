package net.prasenjit.identity.model.api.audit;

import lombok.Data;

@Data
public class SearchAuditRequest {
    private String eventName;
    private String authType;
    private String exceptionName;
    private String exceptionMessage;
    private String principleName;
    private String remoteIp;
    private String sessionId;
    private String message;
}
