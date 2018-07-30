package net.prasenjit.identity.model;

import lombok.Data;
import net.minidev.json.JSONObject;

import java.util.List;

@Data
public class JwksResponse {
    List<JSONObject> keys;
}
