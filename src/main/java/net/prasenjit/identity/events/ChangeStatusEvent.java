package net.prasenjit.identity.events;

import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.Status;

public class ChangeStatusEvent extends AbstractModificationEvent {
	private static final long serialVersionUID = -1902071920793713373L;
	private final Status status;

    /**
     * Create a new ApplicationEvent.
     *
     * @param source the object on which the event initially occurred (never {@code null})
     * @param status the end status in the status change operation
     */
    public ChangeStatusEvent(Object source, ResourceType type, String id, Status status) {
        super(source, type, id);
        this.status = status;
    }

    @Override
    protected String prepareMessage() {
        return "Status changed for " + getUserType() + " '" + id + "' to " + status;
    }

}
