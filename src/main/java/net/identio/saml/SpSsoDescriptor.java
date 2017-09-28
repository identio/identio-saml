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

import net.identio.saml.utils.Assert;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a SP SSO Descriptor used in SAML Metadatas
 *
 * @author Loeiz TANGUY
 *
 */
public class SpSsoDescriptor {

	private List<String> nameIDFormat;
	private boolean wantAssertionsSigned;
	private boolean authentRequestSigned;
	private ArrayList<Endpoint> assertionConsumerServices = new ArrayList<>();
	private ArrayList<X509Certificate> signingCertificates = new ArrayList<>();

	public static SpSsoDescriptor getInstance() {
		return new SpSsoDescriptor();
	}

	/**
	 * Get the list of signing certificates
	 *
	 * @return The list of signing certificates
	 */
	public ArrayList<X509Certificate> getSigningCertificates() {
		return signingCertificates == null ? null : new ArrayList<>(signingCertificates);
	}

	/**
	 * Set the list of signing certificates
	 * 
	 * @param signingCertificates
	 *            The list of signing certificates
	 * @return The current SpSsoDescriptor
	 */
	public SpSsoDescriptor setSigningCertificates(List<X509Certificate> signingCertificates) {
		Assert.notNull(signingCertificates, "Signing certificates can't be null");
		this.signingCertificates = new ArrayList<>(signingCertificates);
		return this;
	}

	/**
	 * Defines if the SP wants assertions in response to be signed
	 *
	 * @return True if the SP wants assertions in response to be signed
	 */

	public boolean isWantAssertionsSigned() {
		return wantAssertionsSigned;
	}

	/**
	 * Set if the SP wants assertions to be signed
	 *
	 * @param wantAssertionsSigned
	 *            True if the SP wants assertions to be signed
	 * @return The current SpSsoDescriptor
	 */
	public SpSsoDescriptor setWantAssertionsSigned(boolean wantAssertionsSigned) {
		this.wantAssertionsSigned = wantAssertionsSigned;
		return this;
	}

	/**
	 * Get if the SP signs its requests
	 *
	 * @return True if the SP signs its requests
	 */
	public boolean isAuthentRequestSigned() {
		return authentRequestSigned;
	}

	/**
	 * Set if the SP signs its requests
	 *
	 * @param authentRequestSigned
	 *            True if the IDP wants authentication requests to be signed
	 * @return The current SpSsoDescriptor
	 */
	public SpSsoDescriptor setAuthentRequestSigned(boolean authentRequestSigned) {
		this.authentRequestSigned = authentRequestSigned;
		return this;
	}

	/**
	 * Get all assertion consumer endpoints of the SP
	 *
	 * @return The list of ACS endpoints
	 */
	public ArrayList<Endpoint> getAssertionConsumerServices() {
		return assertionConsumerServices == null ? null : new ArrayList<Endpoint>(assertionConsumerServices);
	}

	/**
	 * Defines the SP assertion consumer endpoints
	 *
	 * @param assertionConsumerServices
	 *            List of assertion consumer endpoints
	 * @return The current SpSsoDescriptor
	 */
	public SpSsoDescriptor setAssertionConsumerService(ArrayList<Endpoint> assertionConsumerServices) {
		Assert.notNull(assertionConsumerServices, "NameId formats can't be null");
		this.assertionConsumerServices = new ArrayList<Endpoint>(assertionConsumerServices);
		return this;
	}

	/**
	 * Get the accepted NameId formats
	 * 
	 * @return The NameId formats
	 */
	public List<String> getNameIDFormat() {
		return new ArrayList<String>(nameIDFormat);
	}

	/**
	 * Set the accepted NameId formats
	 * 
	 * @param nameIDFormat
	 *            The NameId formats
	 * @return The current SpSsoDescriptor
	 */
	public SpSsoDescriptor setNameIDFormat(List<String> nameIDFormat) {
		Assert.notNull(nameIDFormat, "NameId formats can't be null");
		this.nameIDFormat = new ArrayList<String>(nameIDFormat);
		return this;
	}
}
