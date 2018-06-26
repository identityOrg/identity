package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_AUTH_AUDIT")
public class AuditEvent {
    @Id
    @GeneratedValue
    @Column(name = "ID", updatable = false)
    private Long id;

    @Column(name = "EVENT_NAME", updatable = false, nullable = false)
    private String eventName;

    @Column(name = "EVENT_TIME", updatable = false, nullable = false)
    private LocalDateTime eventTime;

    @Column(name = "AUTH_TYPE", updatable = false)
    private String authType;

    @Column(name = "EXCEPTION_NAME", updatable = false)
    private String exceptionName;

    @Column(name = "EXCEPTION_MESSAGE", updatable = false)
    private String exceptionMessage;

    @Column(name = "PRINCIPLE_NAME", updatable = false)
    private String principleName;

    @Column(name = "PRINCIPLE_TYPE", updatable = false)
    private String principleType;

    @Column(name = "REMOTE_IP", updatable = false)
    private String remoteIp;

    @Column(name = "SESSION_ID", updatable = false)
    private String sessionId;

    @Column(name = "MESSAGE", updatable = false)
    private String message;
}
