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

package net.identio.saml.common;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

/**
 * Security class to limit the key authorized only to those that respect
 * authorized signature methods.
 *
 * @author Loeiz TANGUY
 */
public class X509KeySelector extends KeySelector {

	/**
	 * Attempts to find a key that satisfies the specified constraints. it's the
	 * first public key contained in X509 certificate that match the authorized
	 * signature methods.
	 *
	 * @param keyInfo
	 *            KeyInfo of the document
	 * @param context
	 *            Crypto context
	 * @param method
	 *            Algorithm
	 * @param purpose
	 *            Purpose
	 * 
	 * @return A key that satisfies the constraints
	 * 
	 * @throws KeySelectorException Thrown when no keys are found in the document
	 */
	@SuppressWarnings("rawtypes")
	@Override
	public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method,
			XMLCryptoContext context) throws KeySelectorException {

		Iterator ki = keyInfo.getContent().iterator();
		while (ki.hasNext()) {
			XMLStructure info = (XMLStructure) ki.next();
			if (!(info instanceof X509Data)) {
				continue;
			}
			X509Data x509Data = (X509Data) info;
			Iterator xi = x509Data.getContent().iterator();
			while (xi.hasNext()) {
				Object o = xi.next();
				if (!(o instanceof X509Certificate)) {
					continue;
				}
				final PublicKey publicKey = ((X509Certificate) o).getPublicKey();

				return new KeySelectorResult() {
					@Override
					public Key getKey() {
						return publicKey;
					}
				};

			}
		}

		throw new KeySelectorException("No key found!");
	}
}
