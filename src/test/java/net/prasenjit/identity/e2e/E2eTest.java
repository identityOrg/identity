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

package net.prasenjit.identity.e2e;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.prasenjit.identity.HtmlPageTestBase;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.service.ClientService;
import net.prasenjit.identity.service.CodeFactory;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.time.LocalDateTime;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


public class E2eTest extends HtmlPageTestBase {

    @Autowired
    private CodeFactory codeFactory;

    @Autowired
    private ClientService clientService;


    @Test
    public void testEncryptionDecryption() throws Exception {

        ClientID clientID = new ClientID("client");
        UserDetails client = clientService.loadUserByUsername(clientID.getValue());
        Scope openid = Scope.parse("openid");
        BearerAccessToken createAccessToken = codeFactory.createAccessToken(Profile.create(client), clientID, Duration.ofMinutes(1),
                openid, LocalDateTime.now(), null);

        String token = createAccessToken.getValue();
        mockMvc.perform(get("/api/e2e")
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.publicExponent", notNullValue()))
                .andExpect(jsonPath("$.modulus", notNullValue())).andReturn();
    }
}
