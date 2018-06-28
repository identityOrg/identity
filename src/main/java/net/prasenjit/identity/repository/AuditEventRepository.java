package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository("AuditEventRepository")
public interface AuditEventRepository extends JpaRepository<AuditEvent, String> {
    @Query("select a from AuditEvent as a where a.authType = 'FORM' and a.principleType='USER'" +
            " and a.principleName = ?1 and a.eventTime > ?2 order by a.eventTime desc")
    List<AuditEvent> last7DaysEventforUserFormLogin(String principle,
                                                    LocalDateTime eventTime);
}
