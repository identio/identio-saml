/*
Ident.io SAML API
 Copyright (C) Loeiz TANGUY, All rights reserved.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

package net.identio.saml.tests;

import java.util.ArrayList;

import org.junit.Test;
import org.joda.time.DateTime;
import org.junit.Assert;
import net.identio.saml.AuthentRequest;
import net.identio.saml.AuthentRequestBuilder;
import net.identio.saml.SamlConstants;
import net.identio.saml.exceptions.InvalidRequestException;
import net.identio.saml.exceptions.TechnicalException;

public class AuthentRequestTests {

	@Test
	public void generateAndParseTest() {

		try {

			String version = "2.0";
			String destination = "http://idp.identio.net/SAML2";
			String issuer = "http://sp1.identio.net/sp/SAML2";
			boolean isPassive = false;
			boolean forceAuthn = false;
			String comparison = SamlConstants.COMPARISON_EXACT;
			String userId = "user1";
			String userIdFormat = SamlConstants.NAMEID_UNSPECIFIED;

			ArrayList<String> reqAuthnCtx = new ArrayList<>();
			reqAuthnCtx.add("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
			reqAuthnCtx.add("urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient");

			// Generate ar
			AuthentRequest ar = AuthentRequestBuilder.getInstance().setDestination(destination)
					.setForceAuthent(forceAuthn).setIsPassive(isPassive).setIssuer(issuer)
					.setRequestedAuthnContext(reqAuthnCtx, comparison).setSubject(userId, userIdFormat).build();

			// Extract generated ID and issue instant
			String id = ar.getId();
			DateTime issueInstant = ar.getIssueInstant();

			// Convert it to String
			String arString = ar.toString();

			// Parse it again
			AuthentRequest parsedAr = AuthentRequestBuilder.getInstance().build(arString, false);

			// Check that the parsed values are correct
			Assert.assertEquals(version, parsedAr.getVersion());
			Assert.assertEquals(destination, parsedAr.getDestination());
			Assert.assertEquals(issuer, parsedAr.getIssuer());
			Assert.assertEquals(isPassive, parsedAr.isIsPassive());
			Assert.assertEquals(forceAuthn, parsedAr.isForceAuthn());
			Assert.assertEquals(comparison, parsedAr.getAuthnContextComparison());
			Assert.assertEquals(reqAuthnCtx, parsedAr.getRequestedAuthnContext());
			Assert.assertEquals(userId, parsedAr.getSubjectNameID());
			Assert.assertEquals(userIdFormat, parsedAr.getSubjectNameIDFormat());
			Assert.assertEquals(id, parsedAr.getId());
			Assert.assertEquals(issueInstant, parsedAr.getIssueInstant());
			Assert.assertEquals(false, parsedAr.isSigned());

		} catch (TechnicalException | InvalidRequestException e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void generateAndParseBase64Test() {

		try {

			String version = "2.0";
			String destination = "http://idp.identio.net/SAML2";
			String issuer = "http://sp1.identio.net/sp/SAML2";
			boolean isPassive = false;
			boolean forceAuthn = false;
			String comparison = SamlConstants.COMPARISON_EXACT;
			String userId = "user1";
			String userIdFormat = SamlConstants.NAMEID_UNSPECIFIED;

			ArrayList<String> reqAuthnCtx = new ArrayList<>();
			reqAuthnCtx.add("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

			// Generate a request
			AuthentRequest ar = AuthentRequestBuilder.getInstance().setDestination(destination)
					.setForceAuthent(forceAuthn).setIsPassive(isPassive).setIssuer(issuer)
					.setRequestedAuthnContext(reqAuthnCtx, comparison).setSubject(userId, userIdFormat).build();

			// Extract generated ID and issue instant
			String id = ar.getId();
			DateTime issueInstant = ar.getIssueInstant();

			// Convert it to String
			String arString = ar.toBase64();

			// Parse it again
			AuthentRequest parsedAr = AuthentRequestBuilder.getInstance().build(arString, true);

			// Check that the parsed values are correct
			Assert.assertEquals(version, parsedAr.getVersion());
			Assert.assertEquals(destination, parsedAr.getDestination());
			Assert.assertEquals(issuer, parsedAr.getIssuer());
			Assert.assertEquals(isPassive, parsedAr.isIsPassive());
			Assert.assertEquals(forceAuthn, parsedAr.isForceAuthn());
			Assert.assertEquals(comparison, parsedAr.getAuthnContextComparison());
			Assert.assertEquals(reqAuthnCtx, parsedAr.getRequestedAuthnContext());
			Assert.assertEquals(userId, parsedAr.getSubjectNameID());
			Assert.assertEquals(userIdFormat, parsedAr.getSubjectNameIDFormat());
			Assert.assertEquals(id, parsedAr.getId());
			Assert.assertEquals(issueInstant, parsedAr.getIssueInstant());
			Assert.assertEquals(false, parsedAr.isSigned());

		} catch (TechnicalException | InvalidRequestException e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void generateAndParseEmptyComparisonTest() {

		try {

			String destination = "http://idp.identio.net/SAML2";
			String issuer = "http://sp1.identio.net/sp/SAML2";
			boolean isPassive = false;
			boolean forceAuthn = false;
			String comparison = null;
			String userId = "user1";
			String userIdFormat = SamlConstants.NAMEID_UNSPECIFIED;

			ArrayList<String> reqAuthnCtx = new ArrayList<>();
			reqAuthnCtx.add("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

			// Generate and parse
			AuthentRequest parsedAr = AuthentRequestBuilder.getInstance()
					.build(AuthentRequestBuilder.getInstance().setDestination(destination).setForceAuthent(forceAuthn)
							.setIsPassive(isPassive).setIssuer(issuer).setRequestedAuthnContext(reqAuthnCtx, comparison)
							.setSubject(userId, userIdFormat).build().toString(), false);

			// Check that the parsed values are correct
			Assert.assertEquals(SamlConstants.COMPARISON_EXACT, parsedAr.getAuthnContextComparison());

		} catch (TechnicalException | InvalidRequestException e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void parseEmptyComparisonTest() {

		try {

			String request = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Destination=\"http://idp.identio.net/SAML2\" ForceAuthn=\"false\" ID=\"iio-d7275183-5662-4e10-8717-40b98fdc4cce\" IsPassive=\"false\" IssueInstant=\"2015-12-07T16:48:44Z\" Version=\"2.0\"><saml:Issuer>http://sp1.identio.net/sp/SAML2</saml:Issuer><samlp:RequestedAuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">user1</saml:NameID></saml:Subject></samlp:AuthnRequest>";

			// Generate a request
			AuthentRequest ar = AuthentRequestBuilder.getInstance().build(request, false);

			// Check that the parsed values are correct
			Assert.assertEquals(SamlConstants.COMPARISON_EXACT, ar.getAuthnContextComparison());

		} catch (TechnicalException | InvalidRequestException e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test(expected = InvalidRequestException.class)
	public void twoRequestsTest() throws InvalidRequestException {

		String request = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><root><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Destination=\"http://idp.identio.net/SAML2\" ForceAuthn=\"false\" ID=\"iio-d7275183-5662-4e10-8717-40b98fdc4cce\" IsPassive=\"false\" IssueInstant=\"2015-12-07T16:48:44Z\" Version=\"2.0\"><saml:Issuer>http://sp1.identio.net/sp/SAML2</saml:Issuer><samlp:RequestedAuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">user1</saml:NameID></saml:Subject></samlp:AuthnRequest><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Destination=\"http://idp.identio.net/SAML2\" ForceAuthn=\"false\" ID=\"iio-d7275183-5662-4e10-8717-40b98fdc4cce\" IsPassive=\"false\" IssueInstant=\"2015-12-07T16:48:44Z\" Version=\"2.0\"><saml:Issuer>http://sp1.identio.net/sp/SAML2</saml:Issuer><samlp:RequestedAuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">user1</saml:NameID></saml:Subject></samlp:AuthnRequest></root>";

		// Generate a request
		try {
			AuthentRequestBuilder.getInstance().build(request, false);
		} catch (TechnicalException e) {
			Assert.fail(e.getMessage());
		}

	}

	@Test
	public void generateAndParseEmptyAuthentClassRef() {

		try {
			String destination = "http://idp.identio.net/SAML2";
			String issuer = "http://sp1.identio.net/sp/SAML2";
			boolean isPassive = false;
			boolean forceAuthn = false;
			String userId = "user1";
			String userIdFormat = SamlConstants.NAMEID_UNSPECIFIED;

			// Generate a request
			AuthentRequest parsedAr = AuthentRequestBuilder.getInstance().build(AuthentRequestBuilder.getInstance()
					.setDestination(destination).setForceAuthent(forceAuthn).setIsPassive(isPassive).setIssuer(issuer)
					.setSubject(userId, userIdFormat).build().toString(), false);

			Assert.assertEquals(null, parsedAr.getAuthnContextComparison());
			Assert.assertEquals(null, parsedAr.getRequestedAuthnContext());

		} catch (TechnicalException | InvalidRequestException e) {
			Assert.fail(e.getMessage());
		}

	}

	@Test
	public void generateAndParseSubjectIdRef() {

		try {
			String destination = "http://idp.identio.net/SAML2";
			String issuer = "http://sp1.identio.net/sp/SAML2";
			boolean isPassive = false;
			boolean forceAuthn = false;
			String userId = "user1";
			String userIdFormat = SamlConstants.NAMEID_UNSPECIFIED;

			// Generate a request with the userId and userIdFormat present
			AuthentRequest parsedAr = AuthentRequestBuilder.getInstance().build(AuthentRequestBuilder.getInstance()
					.setDestination(destination).setForceAuthent(forceAuthn).setIsPassive(isPassive).setIssuer(issuer)
					.setSubject(userId, userIdFormat).build().toString(), false);

			// The subjectId and format should be provided
			Assert.assertEquals(parsedAr.getSubjectNameID(), userId);
			Assert.assertEquals(parsedAr.getSubjectNameIDFormat(), SamlConstants.NAMEID_UNSPECIFIED);

			// Now test with an empty format
			parsedAr = AuthentRequestBuilder.getInstance().build(
					AuthentRequestBuilder.getInstance().setDestination(destination).setForceAuthent(forceAuthn)
							.setIsPassive(isPassive).setIssuer(issuer).setSubject(userId, null).build().toString(),
					false);

			// The subjectId should be provided
			Assert.assertEquals(userId, parsedAr.getSubjectNameID());
			Assert.assertEquals(null, parsedAr.getSubjectNameIDFormat());

			// Now test with an empty userId
			parsedAr = AuthentRequestBuilder.getInstance().build(AuthentRequestBuilder.getInstance().setDestination(destination)
					.setForceAuthent(forceAuthn).setIsPassive(isPassive).setIssuer(issuer)
					.setSubject(null, SamlConstants.NAMEID_UNSPECIFIED).build().toString(), false);

			// Both values should be null
			Assert.assertEquals(null, parsedAr.getSubjectNameID());
			Assert.assertEquals(null, parsedAr.getSubjectNameIDFormat());

			// Now test with both null values
			parsedAr = AuthentRequestBuilder.getInstance().build(
					AuthentRequestBuilder.getInstance().setDestination(destination).setForceAuthent(forceAuthn)
							.setIsPassive(isPassive).setIssuer(issuer).setSubject(null, null).build().toString(),
					false);

			// Both values should be null
			Assert.assertEquals(null, parsedAr.getSubjectNameID());
			Assert.assertEquals(null, parsedAr.getSubjectNameIDFormat());

		} catch (TechnicalException | InvalidRequestException e) {
			Assert.fail(e.getMessage());
		}

	}

}
