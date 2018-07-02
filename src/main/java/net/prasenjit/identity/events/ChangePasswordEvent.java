package net.prasenjit.identity.events;

import net.prasenjit.identity.entity.ResourceType;

public class ChangePasswordEvent extends AbstractModificationEvent {

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
