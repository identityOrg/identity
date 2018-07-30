package net.prasenjit.identity.model.openid.discovery;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class DiscoveryResponse {

    private String subject;
    private List<Link> links = new ArrayList<>();

    @Data
    @AllArgsConstructor
    public static class Link {
        private String rel;
        private String href;
    }
}
