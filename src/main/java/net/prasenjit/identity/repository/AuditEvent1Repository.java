package net.prasenjit.identity.repository;

import net.prasenjit.identity.entity.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEvent1Repository extends JpaRepository<AuditEvent, String> {
}
