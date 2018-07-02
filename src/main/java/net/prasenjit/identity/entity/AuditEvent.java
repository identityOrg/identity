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
    @Enumerated(value = EnumType.STRING)
    private AuthenticationType authType;

    /**
     * Display level stands for severity of the event.<br>
     * <ol>
     * <li><b>-2</b> stands for success login</li>
     * <li><b>-1</b> stands for success related events</li>
     * <li><b>+1</b> stands for update events</li>
     * <li><b>+2</b> stands for failure login</li>
     * </ol>
     * Only <b>+2</b> is counted for user lockout
     */
    @Column(name = "DISPLAY_LEVEL", updatable = false)
    private int displayLevel;

    @Column(name = "PRINCIPLE_NAME", updatable = false)
    private String principleName;

    @Column(name = "PRINCIPLE_TYPE", updatable = false)
    @Enumerated(value = EnumType.STRING)
    private PrincipleType principleType;

    @Column(name = "RESOURCE_ID", updatable = false)
    private String resourceId;

    @Column(name = "RESOURCE_TYPE", updatable = false)
    @Enumerated(value = EnumType.STRING)
    private ResourceType resourceType;

    @Column(name = "EXCEPTION_NAME", updatable = false)
    private String exceptionName;

    @Column(name = "EXCEPTION_MESSAGE", updatable = false)
    private String exceptionMessage;

    @Column(name = "REMOTE_IP", updatable = false)
    private String remoteIp;

    @Column(name = "SESSION_ID", updatable = false)
    private String sessionId;

    @Column(name = "MESSAGE", updatable = false)
    private String message;
}
