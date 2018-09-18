package net.prasenjit.identity.events;

import net.prasenjit.identity.entity.ResourceType;

public class CreateEvent extends AbstractModificationEvent {
	private static final long serialVersionUID = -7641488212355729225L;

	/**
     * Create a new ApplicationEvent.
     *
     * @param source the object on which the event initially occurred (never {@code null})
     */
    public CreateEvent(Object source, ResourceType type, String id) {
        super(source, type, id);
    }

    @Override
    protected String prepareMessage() {
        return "New " + getUserType() + " created with id '" + id + "'";
    }

}
