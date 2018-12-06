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

package net.prasenjit.identity.model;

import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.State;
import lombok.Getter;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IdentityViewResponse extends AuthorizationResponse {

    @Getter
    private ViewType viewType;
    @Getter
    private ErrorObject errorObject;
    @Getter
    private Map<String, String> attributes = new HashMap<>();

    public IdentityViewResponse(ViewType viewType) {
        super(URI.create("http://localhost"), (State) null, null);
        this.viewType = viewType;
    }

    public IdentityViewResponse(ErrorObject errorObject) {
        this(ViewType.ERROR);
        this.errorObject = errorObject;
    }

    @Override
    public ResponseMode impliedResponseMode() {
        return null;
    }

    @Override
    public Map<String, List<String>> toParameters() {
        return null;
    }

    @Override
    public boolean indicatesSuccess() {
        return false;
    }

    public enum ViewType {
        LOGIN("login"),
        CONSENT("authorize"),
        ERROR("req-error");

        @Getter
        private final String viewName;

        ViewType(String viewName) {
            this.viewName = viewName;
        }
    }
}
