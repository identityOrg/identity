package net.prasenjit.identity.model.api.user;

import net.minidev.json.JSONObject;
import net.prasenjit.identity.entity.user.User;

public class UserDTO extends User {

    public UserDTO(User user) {
        setLocked(user.getLocked());
        setActive(user.getActive());
        setAdmin(user.getAdmin());
        setPasswordExpiryDate(user.getPasswordExpiryDate());
        setUsername(user.getUsername());
        setCreationDate(user.getCreationDate());
        setExpiryDate(user.getExpiryDate());
        setUserInfo(user.getUserInfo());
    }

    public JSONObject getUserClaims() {
        return getUserInfo().toJSONObject();
    }
}
