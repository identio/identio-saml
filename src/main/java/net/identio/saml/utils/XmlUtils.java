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
package net.identio.saml.utils;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for XML processing
 *
 * @author Loeiz TANGUY
 *
 */
public class XmlUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XmlUtils.class);

	/**
	 * Utility method to generate a secure XML document builder
	 * 
	 * @return a secure document builder
	 * @throws ParserConfigurationException
	 *             Thrown when something went wrong when generating a new
	 *             document builder
	 */
	public static DocumentBuilder getSecureDocumentBuilder() throws ParserConfigurationException {

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);

		try {
			factory.setFeature("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
		} catch (IllegalArgumentException e) {
			LOG.warn("Could not set external-general-entities on documentbuilder to protect againt XXE attacks.");
		}
		try {
			factory.setFeature("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
		} catch (IllegalArgumentException e) {
			LOG.warn("Could not set external-parameter-entities on documentbuilder to protect againt XXE attacks.");
		}
		try {
			factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
		} catch (IllegalArgumentException e) {
			LOG.warn("Could not set disallow-doctype-decl on documentbuilder to protect againt XXE attacks.");
		}
		try {
			factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", Boolean.FALSE);
		} catch (IllegalArgumentException e) {
			LOG.warn("Could not set load-external-dtd on documentbuilder to protect againt XXE attacks.");
		}
		try {
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		} catch (ParserConfigurationException e) {
			LOG.warn("Could not set SECURE_PROCESSING on documentbuilder to protect againt XXE attacks.");
		}

		return factory.newDocumentBuilder();
	}
}
