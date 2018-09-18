package net.prasenjit.identity.events;

import net.prasenjit.identity.entity.AuditEvent;
import net.prasenjit.identity.entity.ResourceType;
import org.springframework.context.ApplicationEvent;

import java.time.LocalDateTime;

public abstract class AbstractModificationEvent extends ApplicationEvent {
	private static final long serialVersionUID = -3909826132531495974L;
	protected final String id;
    protected final ResourceType type;

    /**
     * Create a new ApplicationEvent.
     *
     * @param source the object on which the event initially occurred (never {@code null})
     * @param type   type of the resource
     * @param id     identifier of the resource
     */
    AbstractModificationEvent(Object source, ResourceType type, String id) {
        super(source);
        this.type = type;
        this.id = id;
    }

    /**
     * Create a audit object to insert into audit table
     *
     * @return AuditEvent object
     */
    public AuditEvent createAudit() {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(this.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setMessage(prepareMessage());
        audit.setDisplayLevel(1);
        audit.setResourceId(id);
        audit.setResourceType(type);
        return audit;
    }

    protected abstract String prepareMessage();

    String getUserType() {
        return type.name().toLowerCase();
    }

}
