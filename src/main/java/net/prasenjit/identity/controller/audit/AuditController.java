package net.prasenjit.identity.controller.audit;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.AuditEvent;
import net.prasenjit.identity.model.api.audit.SearchAuditRequest;
import net.prasenjit.identity.repository.AuditEventRepository;
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

    private final AuditEventRepository auditRepository;

    @Override
    @GetMapping
    public List<AuditEvent> searchAudit(@ModelAttribute SearchAuditRequest searchAuditRequest) {
        //AuditEvent audit = new AuditEvent();
        //BeanUtils.copyProperties(searchAuditRequest, audit);

        //ExampleMatcher matcher = ExampleMatcher.matchingAny()
        //        .withMatcher("displayLevel", match -> match.caseSensitive())
        //Example<AuditEvent> auditEx = Example.of(audit, matcher);
        return auditRepository.findByDisplayLevelGreaterThan(searchAuditRequest.getDisplayLevel());
    }
}
