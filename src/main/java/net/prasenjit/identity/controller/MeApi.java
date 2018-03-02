package net.prasenjit.identity.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

@Api(value = "ME", tags = "me", description = "A API which returns the user profile")
public interface MeApi {
    @ApiOperation(value = "Get Profile", notes = "Returns the user profile of the user/client identified by token")
    @ApiResponses(
            @ApiResponse(code = 200, message = "Success")
    )
    UserDetails me(Authentication authentication);
}
