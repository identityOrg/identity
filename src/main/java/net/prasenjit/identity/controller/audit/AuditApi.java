package net.prasenjit.identity.controller.audit;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import net.prasenjit.identity.entity.AuditEvent;
import net.prasenjit.identity.model.api.audit.SearchAuditRequest;

import java.util.List;

@Api(value = "Audit", tags = "audit", description = "API's for audit event retrieval")
public interface AuditApi {
    @ApiOperation(value = "Search Audit", notes = "Search audits for display")
    List<AuditEvent> searchAudit(SearchAuditRequest audit);
}
