package net.prasenjit.identity.events;

import net.prasenjit.identity.entity.ResourceType;

public class UpdateEvent extends AbstractModificationEvent {

    /**
     * Create a new ApplicationEvent.
     *
     * @param source the object on which the event initially occurred (never {@code null})
     */
    public UpdateEvent(Object source, ResourceType type, String id) {
        super(source, type, id);
    }

    @Override
    protected String prepareMessage() {
        return "Updated " + getUserType() + " '" + id + "'";
    }

}
