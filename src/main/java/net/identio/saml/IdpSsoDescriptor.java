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
 * Represents an IDP SSO Descriptor used in SAML Metadatas
 *
 * @author Loeiz TANGUY
 *
 */
public class IdpSsoDescriptor {

	private List<String> nameIDFormat;
	private ArrayList<X509Certificate> signingCertificates = new ArrayList<>();
	private boolean wantAuthnRequestsSigned;
	private ArrayList<Endpoint> ssoEndpoints = new ArrayList<>();

	public static IdpSsoDescriptor getInstance() {
		return new IdpSsoDescriptor();
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
	 * @return The current IdpSsoDescriptor
	 */
	public IdpSsoDescriptor setSigningCertificates(List<X509Certificate> signingCertificates) {
		Assert.notNull(signingCertificates, "Signing certificates can't be null");
		this.signingCertificates = new ArrayList<>(signingCertificates);
		return this;
	}

	/**
	 * Get boolean defining if the IDP wants authentication requests to be
	 * signed
	 *
	 * @return True if the IDP wants authentication requests to be signed
	 */
	public boolean isWantAuthnRequestsSigned() {
		return wantAuthnRequestsSigned;
	}

	/**
	 * Defines if the IDP wants authentication requests to be signed
	 * 
	 * @param wantAuthnRequestsSigned
	 *            True if the IDP wants authentication requests to be signed
	 * @return The current IdpSsoDescriptor
	 */
	public IdpSsoDescriptor setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
		this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
		return this;
	}

	/**
	 * Get all SSO endpoints of the IDP
	 *
	 * @return The list of SSO endpoints
	 */
	public ArrayList<Endpoint> getSsoEndpoints() {
		return ssoEndpoints == null ? null : new ArrayList<Endpoint>(ssoEndpoints);
	}

	/**
	 * Set all SSO endpoints of the IDP
	 * 
	 * @param ssoEndpoints
	 *            The list of SSO endpoints
	 * @return The current IdpSsoDescriptor
	 */
	public IdpSsoDescriptor setSsoEndpoints(ArrayList<Endpoint> ssoEndpoints) {
		Assert.notNull(ssoEndpoints, "Endpoints can't be null");
		this.ssoEndpoints = new ArrayList<Endpoint>(ssoEndpoints);
		return this;
	}

	/**
	 * Get the accepted NameId formats
	 * 
	 * @return The NameId formats
	 */
	public List<String> getNameIDFormat() {
		return nameIDFormat == null ? null : new ArrayList<String>(nameIDFormat);
	}

	/**
	 * Set the accepted NameId formats
	 * 
	 * @param nameIDFormat
	 *            The NameId formats
	 * @return The current IdpSsoDescriptor
	 */
	public IdpSsoDescriptor setNameIDFormat(List<String> nameIDFormat) {
		Assert.notNull(nameIDFormat, "NameId formats can't be null");
		this.nameIDFormat = new ArrayList<String>(nameIDFormat);
		return this;
	}

}
