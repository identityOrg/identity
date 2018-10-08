/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

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
