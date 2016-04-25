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

package net.identio.saml;

import java.util.ArrayList;

import org.codehaus.stax2.XMLInputFactory2;
import org.codehaus.stax2.XMLOutputFactory2;

import net.identio.saml.exceptions.InvalidRequestException;
import net.identio.saml.exceptions.TechnicalException;

/**
 * SAML authentication requests builder. This class must be used to generate a
 * SAML request.
 *
 * @author Loeiz TANGUY
 *
 */
public class AuthentRequestBuilder {

	private String issuer;
	private String destination;
	private String subjectID;
	private String subjectType;
	private boolean forceAuthent;
	private boolean passive;
	private String authnClassComparison = SamlConstants.COMPARISON_EXACT;
	private ArrayList<String> requestedAuthnContext;
	private Endpoint preferredEndpoint;
	private boolean preferEndpointIndex;
	private String version = "2.0";

	private static XMLOutputFactory2 xmlof;
	private static XMLInputFactory2 xmlif;

	static {
		xmlof = (XMLOutputFactory2) XMLOutputFactory2.newInstance();
		xmlif = (XMLInputFactory2) XMLInputFactory2.newInstance();

		// Configure factories
		xmlif.setProperty(XMLInputFactory2.IS_REPLACING_ENTITY_REFERENCES, Boolean.FALSE);
		xmlif.setProperty(XMLInputFactory2.SUPPORT_DTD, Boolean.FALSE);
		xmlif.setProperty(XMLInputFactory2.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
		xmlif.setProperty(XMLInputFactory2.IS_COALESCING, Boolean.FALSE);
		xmlif.configureForSpeed();

		xmlof.configureForSpeed();
	}

	protected AuthentRequestBuilder() {
	}

	public static AuthentRequestBuilder getInstance() {
		return new AuthentRequestBuilder();
	}

	/**
	 * Defines the issuer of the request
	 *
	 * @param issuer
	 *            Name of the issuer
	 * @return The current AuthentRequestBuilder
	 */
	public AuthentRequestBuilder setIssuer(String issuer) {
		this.issuer = issuer;
		return this;
	}

	/**
	 * Defines the destination of the request
	 *
	 * @param destination
	 *            Destination URL
	 * @return The current AuthentRequestBuilder
	 */
	public AuthentRequestBuilder setDestination(String destination) {
		this.destination = destination;
		return this;
	}

	/**
	 * Defines if the request must force re-authentication
	 *
	 * @param forceAuthent
	 *            True to force authentication
	 * @return The current AuthentRequestBuilder
	 */
	public AuthentRequestBuilder setForceAuthent(boolean forceAuthent) {
		this.forceAuthent = forceAuthent;
		return this;
	}

	/**
	 * Defines the authentication contexts of the request
	 *
	 * @param authnContext
	 *            Authentication contexts accepted
	 * @param comparison
	 *            The type of comparison to use for this authentication context
	 * @return The current AuthentRequestBuilder
	 */
	public AuthentRequestBuilder setRequestedAuthnContext(ArrayList<String> authnContext, String comparison) {
		this.requestedAuthnContext = new ArrayList<>(authnContext);
		this.authnClassComparison = comparison == null ? SamlConstants.COMPARISON_EXACT : comparison;

		return this;
	}

	/**
	 * Defines if the IDP should be passive
	 *
	 * @param passive
	 *            True to force IDP to be passive
	 * @return The current AuthentRequestBuilder
	 */
	public AuthentRequestBuilder setIsPassive(boolean passive) {
		this.passive = passive;
		return this;
	}

	/**
	 * Defines the subject of the request
	 *
	 * @param id
	 *            User ID
	 * @param type
	 *            Identifier type
	 * @return The current AuthentRequestBuilder
	 */
	public AuthentRequestBuilder setSubject(String id, String type) {
		if (id != null) {
			this.subjectID = id;
			this.subjectType = type;
		}
		return this;
	}

	/**
	 * Defines the prefer ACS endpoint for the SAML response
	 *
	 * @param endpoint
	 *            The preferred endpoint
	 * @param preferEndpointIndex
	 *            Indicates if we want to reference it by index or by
	 *            binding/url
	 * @return The current AuthentRequestBuilder
	 */
	public AuthentRequestBuilder setPreferredEndpoint(Endpoint endpoint, boolean preferEndpointIndex) {
		if (endpoint != null) {
			this.preferredEndpoint = new Endpoint(endpoint);
			this.preferEndpointIndex = preferEndpointIndex;
		}
		return this;
	}

	/**
	 * Build the request
	 *
	 * @return Built request
	 * @throws TechnicalException
	 *             Thrown when something went wrong when building the request
	 */
	public AuthentRequest build() throws TechnicalException {

		AuthentRequest ar = new AuthentRequest();
		ar.init(xmlof, version, issuer, destination, subjectID, subjectType, forceAuthent, passive,
				authnClassComparison, requestedAuthnContext, preferredEndpoint, preferEndpointIndex);

		return ar;
	}

	/**
	 * Build a request from a string containing a SAML request in XML form
	 *
	 * @param authentRequest
	 *            String containing the request
	 * @param base64
	 *            Boolean to indicate that the string is Base64-encoded
	 * 
	 * @return Built request
	 * @throws TechnicalException
	 *             Thrown when something went wrong when building the request
	 * @throws InvalidRequestException
	 *             Thrown when the request doesn't have the awaited format
	 */
	public AuthentRequest build(String authentRequest, boolean base64)
			throws TechnicalException, InvalidRequestException {

		AuthentRequest ar = new AuthentRequest();
		ar.init(xmlif, authentRequest, base64);
		return ar;
	}

}
