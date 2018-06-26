package net.prasenjit.identity.controller.audit;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.AuditEvent;
import net.prasenjit.identity.model.api.audit.SearchAuditRequest;
import net.prasenjit.identity.repository.AuditEvent1Repository;
import org.springframework.beans.BeanUtils;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@SwaggerDocumented
@RequiredArgsConstructor
@RequestMapping(value = "api/audit", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuditController implements AuditApi {

    private final AuditEvent1Repository auditRepository;

    @Override
    @GetMapping
    public List<AuditEvent> searchAudit(@ModelAttribute SearchAuditRequest searchAuditRequest) {
        AuditEvent audit = new AuditEvent();
        BeanUtils.copyProperties(searchAuditRequest, audit);

        Example<AuditEvent> auditEx = Example.of(audit, ExampleMatcher.matchingAny());
        return auditRepository.findAll(auditEx);
    }
}
