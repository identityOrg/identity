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

package net.prasenjit.identity.controller;

import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.RequiredArgsConstructor;
import net.minidev.json.JSONObject;
import net.prasenjit.identity.model.openid.discovery.DiscoveryResponse;
import net.prasenjit.identity.service.openid.MetadataService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class DiscoveryController {

    private final MetadataService metadataService;

    @GetMapping("/.well-known/webfinger")
    public DiscoveryResponse webFinder(@RequestParam("resource") String resource, @RequestParam("rel") String rel) {
        return metadataService.findWebFinder(rel, resource);
    }

    @GetMapping({"/.well-known/openid-configuration"})
    public JSONObject oidcConfiguration() {
        OIDCProviderMetadata metadata = metadataService.findOIDCConfiguration();
        return metadata.toJSONObject();
    }

    @GetMapping({"/.well-known/oauth-authorization-server"})
    public JSONObject oauthConfiguration() {
        AuthorizationServerMetadata metadata = metadataService.findOIDCConfiguration();
        return metadata.toJSONObject();
    }
}
