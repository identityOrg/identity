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
