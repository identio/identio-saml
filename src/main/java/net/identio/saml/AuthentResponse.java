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

import net.identio.saml.exceptions.InvalidAssertionException;
import net.identio.saml.exceptions.InvalidAuthentResponseException;
import net.identio.saml.exceptions.TechnicalException;
import net.identio.saml.utils.XmlUtils;
import org.codehaus.stax2.XMLInputFactory2;
import org.codehaus.stax2.XMLOutputFactory2;
import org.codehaus.stax2.XMLStreamReader2;
import org.codehaus.stax2.XMLStreamWriter2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Represents a SAML AuthentResponse. This object can only be constructed
 * through an AuthentResponseBuilder.
 *
 * @author Loeiz TANGUY
 *
 */
public class AuthentResponse extends SignableSAMLObject {

	private static final Logger LOG = LoggerFactory.getLogger(AuthentResponse.class);

	private String version;
	private String issuer;
	private boolean status;
	private String statusMessage;
	private Instant issueInstant;
	private String destination;

	private Assertion assertion;

	protected AuthentResponse() {

	}

	/**
	 * Constructor from a string containing a XML document
	 *
	 * @param xmlif
	 *            StAX XMLInputFactory used to parse the string
	 * @param responseString
	 *            String containing the XML document
	 * @throws TechnicalException
	 * @throws InvalidAuthentResponseException
	 * @throws InvalidAssertionException
	 */
	protected void init(XMLInputFactory2 xmlif, String responseString)
			throws TechnicalException, InvalidAuthentResponseException, InvalidAssertionException {

		LOG.debug("Starting Authentication Response generation...");

		try {

			// Initialize document
			DocumentBuilder db = XmlUtils.getSecureDocumentBuilder();

			this.doc = db.parse(new ByteArrayInputStream(responseString.getBytes("UTF-8")));

			// Parse values to cache them
			XMLStreamReader2 parser = (XMLStreamReader2) xmlif
					.createXMLStreamReader(new ByteArrayInputStream(responseString.getBytes("UTF-8")));

			boolean responseParsed = false;
			boolean assertionParsed = false;

			for (int event = parser.next(); event != XMLStreamConstants.END_DOCUMENT; event = parser.next()) {

				// Ignore everything but a start element
				if (event != XMLStreamConstants.START_ELEMENT) {
					continue;
				}

				switch (parser.getLocalName()) {

				case "Response":

					if (responseParsed) {
						throw new InvalidAuthentResponseException(
								"Invalid Response: two response elements in the submitted SAML response");
					}
					responseParsed = true;

					version = parser.getAttributeValue(null, "Version");
					destination = parser.getAttributeValue(null, "Destination");
					id = parser.getAttributeValue(null, "ID");
					issueInstant = Instant.parse(parser.getAttributeValue(null, "IssueInstant"));
					break;

				case "Signature":
					signed = true;
					break;

				case "Assertion":

					if (assertionParsed) {
						throw new InvalidAuthentResponseException(
								"Invalid Response: two assertion elements in the submitted SAML response");
					}
					assertionParsed = true;
					// We entered the assertion
					buildAssertion(parser, db);
					break;

				// We make sure to get the issuer tag of the Response, not
				// the Assertion
				case "Issuer":
					issuer = parser.getElementText();
					break;

				case "StatusCode":
					status = SamlConstants.STATUS_SUCCESS.equals(parser.getAttributeValue(null, "Value"));
					break;

				case "StatusMessage":
					statusMessage = parser.getElementText();
					break;

				default:
					// Do nothing
					break;
				}
			}

			parser.close();

		} catch (SAXException | XMLStreamException | ParserConfigurationException e) {
			throw new TechnicalException("Error when parsing AuthnResponse", e);
		} catch (IOException e) {
			throw new TechnicalException("I/O error when parsing AuthnResponse", e);
		}
	}

	private void buildAssertion(XMLStreamReader2 parser, DocumentBuilder db)
			throws TechnicalException, InvalidAssertionException {
		
		Node assertionNode = doc.getElementsByTagNameNS(SamlConstants.ASSERTION_NS, "Assertion").item(0);
		Document assertionDoc = db.newDocument();

		Node dup = assertionDoc.importNode(assertionNode, true);
		assertionDoc.appendChild(dup);

		assertion = new Assertion();
		assertion.init(parser, assertionDoc);

		LOG.debug("SAML Authentication Response generated.");
	}

	/**
	 * Constructor from values of the response
	 *
	 * @param xmlof
	 *            StAX XMLOutputFactory used to generate the XML
	 * @param version
	 *            SAML version (usually 2.0)
	 * @param issuer
	 *            Identifier of the issuer
	 * @param assertion
	 *            Embedded assertion
	 * @param status
	 *            Status code
	 * @param statusMessage
	 *            Status message
	 * @param destination
	 *            Destination of the response
	 * @throws TechnicalException
	 */
	protected void init(XMLOutputFactory2 xmlof, String version, String issuer, boolean status, String statusMessage,
			String destination, Assertion assertion) throws TechnicalException {

		LOG.debug("Starting Authentication Response generation...");

		// Cache data
		this.version = version;
		this.issuer = issuer;
		this.status = status;
		this.statusMessage = statusMessage;
		this.destination = destination;
		this.assertion = assertion;

		// Update time-dependent elements
		issueInstant = Instant.now();

		UUID uuid = UUID.randomUUID();
		this.id = SamlConstants.UUID_PREFIX + uuid.toString();

		XMLStreamWriter2 xmlw;
		try {

			DocumentBuilder db = XmlUtils.getSecureDocumentBuilder();
			
			doc = db.newDocument();

			xmlw = (XMLStreamWriter2) xmlof.createXMLStreamWriter(new DOMResult(doc));

			xmlw.writeStartDocument();
			xmlw.setPrefix("samlp", SamlConstants.PROTOCOL_NS);
			xmlw.setPrefix("saml", SamlConstants.ASSERTION_NS);
			xmlw.writeStartElement(SamlConstants.PROTOCOL_NS, "Response");
			xmlw.writeNamespace("samlp", SamlConstants.PROTOCOL_NS);
			xmlw.writeNamespace("saml", SamlConstants.ASSERTION_NS);

			xmlw.writeAttribute("ID", id);
			xmlw.writeAttribute("IssueInstant", issueInstant.toString());
			xmlw.writeAttribute("Version", version);
			xmlw.writeAttribute("Destination", destination);

			// Add issuer
			xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Issuer");
			xmlw.writeCharacters(issuer);
			xmlw.writeEndElement();

			xmlw.writeStartElement(SamlConstants.PROTOCOL_NS, "Status");
			xmlw.writeStartElement(SamlConstants.PROTOCOL_NS, "StatusCode");
			if (status) {
				xmlw.writeAttribute("Value", SamlConstants.STATUS_SUCCESS);
			} else {
				xmlw.writeAttribute("Value", SamlConstants.STATUS_ERROR);
				xmlw.writeEndElement();
				xmlw.writeStartElement(SamlConstants.PROTOCOL_NS, "StatusMessage");
				xmlw.writeCharacters(statusMessage);
			}

			xmlw.writeEndDocument();
			xmlw.close();

			// Add the assertion
			if (assertion != null) {
				Node dup = doc.importNode(assertion.doc.getDocumentElement(), true);
				doc.getDocumentElement().appendChild(dup);
			}

		} catch (XMLStreamException | ParserConfigurationException e) {
			throw new TechnicalException("Error when generating AuthnResponse", e);
		}

		LOG.debug("SAML Authentication Response generated.");
	}

	/**
	 * Get the assertion embedded in the response
	 *
	 * @return Embedded assertion
	 */
	public Assertion getAssertion() {
		return assertion;
	}

	/**
	 * Get the ID of the authentication response
	 *
	 * @return ID of the authentication response
	 */
	public String getID() {
		return id;
	}

	/**
	 * Get the status code from the response
	 *
	 * @return Status code of the response
	 */
	public String getStatusCode() {

		return status ? SamlConstants.STATUS_SUCCESS : SamlConstants.STATUS_ERROR;
	}

	/**
	 * Get the status message from the response
	 *
	 * @return Status message of the response
	 */
	public String getStatusMessage() {
		return statusMessage;
	}

	/**
	 * Get the version of the authentication response
	 *
	 * @return Version of the authentication response
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Get the destination of the authentication response
	 *
	 * @return Destination of the authentication response
	 */
	public String getDestination() {
		return destination;
	}

	/**
	 * Get the issuer of the authentication response
	 *
	 * @return Issuer of the authentication response
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * Get the issue instant of the authentication response
	 *
	 * @return Issue instant of the authentication response
	 */
	public Instant getIssueInstant() {
		return issueInstant;
	}

	/**
	 * Displays the response in a human readable format
	 *
	 * @return Human readable form of the response
	 */
	@Override
	public String toString() {

		LOG.debug("Starting SAML authentication Response conversion to String...");

		String returnValue = "";

		try (StringWriter writer = new StringWriter()) {

			DOMSource domSource = new DOMSource(doc);

			StreamResult result = new StreamResult(writer);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer;

			transformer = tf.newTransformer();

			transformer.transform(domSource, result);

			writer.flush();
			returnValue = writer.toString();

		} catch (TransformerException | IOException e) {
			LOG.error("Error when converting SAML Authentication Response to String", e);
		}

		LOG.debug("SAML Authentication Response converted to String: '{}'", returnValue);

		return returnValue;
	}

	/**
	 * Converts the response in base 64 format
	 *
	 * @return Response in Base 64 format
	 */
	public String toBase64() {

		LOG.debug("Starting B64 encoding of the Authentication Response...");

		String b64s = Base64.getEncoder().encodeToString(this.toString().getBytes()).replaceAll("\r", "").replaceAll("\n", "");

		LOG.debug("Authentication Response b64 encoded: '" + b64s + "'.");

		return b64s;
	}

}
