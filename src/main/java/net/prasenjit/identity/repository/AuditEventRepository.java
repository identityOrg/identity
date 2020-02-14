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

package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository("AuditEventRepository")
public interface AuditEventRepository extends JpaRepository<AuditEvent, String> {
    @Query("select a from AuditEvent as a where a.authType = 'FORM' and a.principleType='USER'" +
            " and a.principleName = ?1 and a.eventTime > ?2 order by a.eventTime desc")
    List<AuditEvent> last7DaysEventForUserFormLogin(String principle, LocalDateTime eventTime);

    List<AuditEvent> findByDisplayLevelGreaterThan(int displayLevel);

    Page<AuditEvent> findByDisplayLevelGreaterThan(int displayLevel, Pageable pageable);
}
