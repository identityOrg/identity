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

package net.prasenjit.identity.controller.audit;

import lombok.RequiredArgsConstructor;
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
