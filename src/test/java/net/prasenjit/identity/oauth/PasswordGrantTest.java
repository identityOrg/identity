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

package net.prasenjit.identity.oauth;

import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.util.Base64Utils;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


public class PasswordGrantTest extends HtmlPageTestBase {

    @Test
    public void testSuccess() throws Exception {
        String credentials = Base64Utils.encodeToString("client:client".getBytes(StandardCharsets.US_ASCII));

        mockMvc.perform(post("/oauth/token")
                .param("grant_type", "client_credentials")
                .param("scope", "openid")
                .header("Authorization", "Basic " + credentials)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(jsonPath("$.access_token", notNullValue()));
    }
}
