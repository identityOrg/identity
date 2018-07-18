package net.prasenjit.identity.controller.discovery;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.model.openid.discovery.DiscoveryResponse;
import net.prasenjit.identity.properties.ServerMetadata;
import net.prasenjit.identity.service.openid.MetadataService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequiredArgsConstructor
public class DiscoveryController {

    private final MetadataService metadataService;

    @GetMapping("/.well-known/webfinger")
    public DiscoveryResponse webFinder(@RequestParam("resource") String resource, @RequestParam("rel") String rel,
                                       UriComponentsBuilder builder) {
        return metadataService.findWebFinder(rel, resource, builder);
    }

    @GetMapping("/.well-known/openid-configuration")
    public ServerMetadata configuration(UriComponentsBuilder builder) {
        return metadataService.findMetadata(builder);
    }
}
