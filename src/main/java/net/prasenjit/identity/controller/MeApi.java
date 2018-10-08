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

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import net.prasenjit.identity.model.openid.StandardClaim;
import org.springframework.security.core.Authentication;

@Api(value = "ME", tags = "me", description = "A API which returns the user profile")
public interface MeApi {
    @ApiOperation(value = "Get Profile", notes = "Returns the user profile of the user/client identified by token")
    @ApiResponses(
            @ApiResponse(code = 200, message = "Success")
    )
    StandardClaim me(Authentication authentication);
}
