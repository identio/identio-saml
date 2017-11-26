/*
 * Ident.io SAML API
 * Copyright (C) 2017 Loeiz TANGUY, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */

package net.identio.saml.tests;

import net.identio.saml.*;
import net.identio.saml.exceptions.InvalidAssertionException;
import net.identio.saml.exceptions.InvalidAuthentResponseException;
import net.identio.saml.exceptions.TechnicalException;
import org.junit.Assert;
import org.junit.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.UUID;

public class AuthentResponseTests {

    @Test
    public void generateAndParseTest() {

        try {

            String version = "2.0";
            String destination = "http://sp1.identio.net/SAML2";
            String destinationEndpoint = "http://sp1.identio.net/SAML2/ACS";
            String issuer = "http://idp.identio.net/sp/SAML2";
            String userId = "user1";
            String requestId = UUID.randomUUID().toString();
            String sessionId = UUID.randomUUID().toString();
            String authnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
            Instant authnInstant = Instant.now();

            ArrayList<String> reqAuthnCtx = new ArrayList<>();
            reqAuthnCtx.add("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
            reqAuthnCtx.add("urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient");

            Assertion assertion = AssertionBuilder.getInstance().setIssuer(issuer)
                    .setSubject(userId, SamlConstants.NAMEID_UNSPECIFIED)
                    .setSubjectConfirmation(SamlConstants.SUBJECT_CONFIRMATION_BEARER, requestId,
                            "http://sp1.identio.net/SAML2/ACS")
                    .setConditions(destination,
                            5,
                            3)
                    .setAuthentStatement(authnContext, authnInstant, sessionId).build();

            // Build the response
            AuthentResponse response = AuthentResponseBuilder.getInstance()
                    .setIssuer(issuer).setStatus(true, null)
                    .setDestination(destinationEndpoint).setAssertion(assertion).build();

            // Extract generated ID and issue instant
            String id = response.getID();
            Instant issueInstant = response.getIssueInstant();

            // Convert it to String
            String arString = response.toString();

            // Parse it again
            AuthentResponse parsedAr = AuthentResponseBuilder.getInstance().build(arString);

            // Check that the parsed values are correct
            Assert.assertEquals(version, parsedAr.getVersion());
            Assert.assertEquals(destinationEndpoint, parsedAr.getDestination());
            Assert.assertEquals(issuer, parsedAr.getIssuer());
            Assert.assertEquals(id, parsedAr.getID());
            Assert.assertEquals(issueInstant, parsedAr.getIssueInstant());
            Assert.assertEquals(false, parsedAr.isSigned());

        } catch (TechnicalException | InvalidAuthentResponseException e) {
            Assert.fail(e.getMessage());
        }
    }

}
