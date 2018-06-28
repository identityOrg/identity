package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository("AuditEventRepository")
public interface AuditEventRepository extends JpaRepository<AuditEvent, String> {
}
