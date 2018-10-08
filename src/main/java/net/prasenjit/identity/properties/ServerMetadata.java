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

package net.prasenjit.identity.properties;

import lombok.Data;

@Data
public class ServerMetadata {
    /**
     * REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer
     * Identifier. If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value
     * returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
     */
    private String issuer;

}
