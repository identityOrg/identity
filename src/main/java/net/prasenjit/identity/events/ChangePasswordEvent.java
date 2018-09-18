package net.prasenjit.identity.events;

import net.prasenjit.identity.entity.ResourceType;

public class ChangePasswordEvent extends AbstractModificationEvent {
	private static final long serialVersionUID = 801437013927150877L;

	/**
     * Create a new ApplicationEvent.
     *
     * @param source the object on which the event initially occurred (never {@code null})
     */
    public ChangePasswordEvent(Object source, ResourceType type, String id) {
        super(source, type, id);
    }

    @Override
    protected String prepareMessage() {
        return "Password changed for " + getUserType() + " '" + id + "'";
    }

}
