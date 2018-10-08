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

package net.prasenjit.identity.entity.user;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Data
@Embeddable
public class UserAddress {
    /**
     * Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple
     * lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair
     * ("\r\n") or as a single line feed character ("\n").
     */
    @Column(name = "ADDRESS_FORMATTED")
    private String formatted;
    /**
     * Full street address component, which MAY include house number, street name, Post Office Box, and multi-line
     * extended street address information. This field MAY contain multiple lines, separated by newlines. Newlines
     * can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
     */
    @Column(name = "ADDRESS_STREET")
    private String street_address;
    /**
     * City or locality component.
     */
    @Column(name = "ADDRESS_LOCALITY")
    private String locality;
    /**
     * State, province, prefecture, or region component.
     */
    @Column(name = "ADDRESS_REGION")
    private String region;
    /**
     * Zip code or postal code component.
     */
    @Column(name = "ADDRESS_POSTAL_CODE")
    private String postal_code;
    /**
     * Country name component.
     */
    @Column(name = "ADDRESS_COUNTRY")
    private String country;
}
