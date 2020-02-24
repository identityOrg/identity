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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.prasenjit.identity.entity.AuditEvent;
import net.prasenjit.identity.model.api.audit.SearchAuditRequest;

import java.util.List;

@Tag(name = "audit", description = "API's for audit event retrieval")
public interface AuditApi {
    @Operation(summary = "Search Audit", description = "Search audits for display")
    List<AuditEvent> searchAudit(SearchAuditRequest audit);
}
