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

import net.identio.saml.exceptions.InvalidRequestException;
import net.identio.saml.exceptions.TechnicalException;
import net.identio.saml.utils.XmlUtils;
import org.codehaus.stax2.XMLInputFactory2;
import org.codehaus.stax2.XMLOutputFactory2;
import org.codehaus.stax2.XMLStreamReader2;
import org.codehaus.stax2.XMLStreamWriter2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.UUID;

/**
 * Represents a SAML authentication request. This object must be constructed
 * through an AuthentRequestBuilder.
 *
 * @author Loeiz TANGUY
 *
 */
public class AuthentRequest extends SignableSAMLObject {

	private static final Logger LOG = LoggerFactory.getLogger(AuthentRequest.class);

	private String version;
	private String issuer;
	private String subjectID;
	private String subjectType;
	private String destination;
	private boolean passive;
	private boolean forceAuthent;
	private Instant issueInstant;
	private String authnClassComparison;
	private Endpoint preferredEndpoint;
	private boolean preferEndpointIndex;

	private ArrayList<String> authnClassRef;

	protected AuthentRequest() {

	}

	/**
	 * Constructor from a string containing a XML document
	 *
	 * @param xmlif
	 *            StAX XMLInputFactory used to parse the string
	 * @param rawRequest
	 *            String containing the XML document
	 * @throws TechnicalException
	 * @throws InvalidRequestException
	 */
	protected void init(XMLInputFactory2 xmlif, String rawRequest, boolean base64)
			throws TechnicalException, InvalidRequestException {
		try {

			String request = rawRequest;
			
			if (base64) {
				request = new String(Base64.getDecoder().decode(request));
			}

			LOG.debug("Starting SAML authentication request generation...");

			DocumentBuilder db = XmlUtils.getSecureDocumentBuilder();

			this.doc = db.parse(new ByteArrayInputStream(request.getBytes()));

			// Parse values to cache them
			XMLStreamReader2 parser = (XMLStreamReader2) xmlif
					.createXMLStreamReader(new ByteArrayInputStream(request.getBytes()));

			boolean requestParsed = false;

			for (int event = parser.next(); event != XMLStreamConstants.END_DOCUMENT; event = parser.next()) {

				
				
				// Ignore everything but a start element
				if (event != XMLStreamConstants.START_ELEMENT) {
					continue;
				}

				switch (parser.getLocalName()) {

				case "AuthnRequest":

					if (requestParsed) {
						throw new InvalidRequestException(
								"Invalid Request: two request elements in the submitted SAML response");
					}

					requestParsed = true;

					version = parser.getAttributeValue(null, "Version");
					destination = parser.getAttributeValue(null, "Destination");
					forceAuthent = Boolean.parseBoolean(parser.getAttributeValue(null, "ForceAuthn"));
					passive = Boolean.parseBoolean(parser.getAttributeValue(null, "IsPassive"));
					id = parser.getAttributeValue(null, "ID");
					issueInstant = Instant.parse(parser.getAttributeValue(null, "IssueInstant"));

					String protocolBinding = parser.getAttributeValue(null, "ProtocolBinding");
					Integer assertionConsumerServiceIndex = null;
					String assertionConsumerServiceIndexString = parser.getAttributeValue(null,
							"AssertionConsumerServiceIndex");
					if (assertionConsumerServiceIndexString != null) {
						assertionConsumerServiceIndex = new Integer(assertionConsumerServiceIndexString);
						preferEndpointIndex = true;
					}
					String assertionConsumerServiceURL = parser.getAttributeValue(null, "AssertionConsumerServiceURL");

					if (protocolBinding != null || assertionConsumerServiceIndex != null
							|| assertionConsumerServiceURL != null) {

						preferredEndpoint = new Endpoint(assertionConsumerServiceIndex, protocolBinding,
								assertionConsumerServiceURL, false);
					}

					break;

				case "Signature":
					signed = true;
					break;

				case "Issuer":
					issuer = parser.getElementText();
					break;

				case "NameID":
					subjectType = parser.getAttributeValue(null, "Format");
					subjectID = parser.getElementText();
					break;

				case "RequestedAuthnContext":
					authnClassComparison = parser.getAttributeValue(null, "Comparison");
					authnClassComparison = authnClassComparison == null ? SamlConstants.COMPARISON_EXACT
							: authnClassComparison;
					break;

				case "AuthnContextClassRef":
					if (authnClassRef == null) {
						authnClassRef = new ArrayList<>();
					}
					authnClassRef.add(parser.getElementText());
					break;
					
				default:
					// Do nothing
					break;
				}

			}

			parser.close();

		} catch (SAXException | ParserConfigurationException | XMLStreamException e) {
			throw new TechnicalException("Error when parsing AuthnRequest", e);
		} catch (IOException e) {
			throw new TechnicalException("I/O error when parsing AuthnRequest", e);
		} catch (IllegalArgumentException e) {
			throw new TechnicalException("Impossible to decode Base64-encoded request", e);
		}

		LOG.debug("SAML authentication request generated.");

	}

	/**
	 * Constructor from values of the request
	 *
	 * @param xmlof
	 *            StAX XMLOutputFactory used to generate the XML
	 * @param version
	 *            SAML version (usually 2.0)
	 * @param issuer
	 *            Identifier of the issuer
	 * @param destination
	 *            Destination of the request
	 * @param subjectID
	 *            Identifier of the subject
	 * @param subjectType
	 *            Type of the subject
	 * @param forceAuthent
	 *            Indicates if an authentication should be forced
	 * @param passive
	 *            Indicates if the idp is allowed to interact with the user
	 * @param authnClassComparison
	 *            Type of comparison for authentication context
	 * @param authnClassRef
	 *            Requested authentication context
	 * @throws TechnicalException
	 */
	protected void init(XMLOutputFactory2 xmlof, String version, String issuer, String destination, String subjectID,
			String subjectType, boolean forceAuthent, boolean passive, String authnClassComparison,
			ArrayList<String> authnClassRef, Endpoint preferredEndpoint, boolean preferEndpointIndex)
					throws TechnicalException {

		LOG.debug("Starting SAML authentication request generation...");

		// Cache data
		this.version = version;
		this.issuer = issuer;
		this.subjectID = subjectID;
		this.subjectType = subjectType;
		this.destination = destination;
		this.forceAuthent = forceAuthent;
		this.passive = passive;
		this.authnClassComparison = authnClassComparison;
		this.authnClassRef = authnClassRef;
		this.preferredEndpoint = preferredEndpoint;
		this.preferEndpointIndex = preferEndpointIndex;

		// Update time-dependent parameters
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
			xmlw.writeStartElement(SamlConstants.PROTOCOL_NS, "AuthnRequest");
			xmlw.writeNamespace("samlp", SamlConstants.PROTOCOL_NS);
			xmlw.writeNamespace("saml", SamlConstants.ASSERTION_NS);

			xmlw.writeAttribute("ID", id);
			xmlw.writeAttribute("IssueInstant", issueInstant.toString());
			xmlw.writeAttribute("Version", version);
			xmlw.writeAttribute("Destination", destination);
			xmlw.writeAttribute("ForceAuthn", Boolean.toString(forceAuthent));
			xmlw.writeAttribute("IsPassive", Boolean.toString(passive));

			// Add the prefered ACS if specified
			if (preferredEndpoint != null) {
				if (preferEndpointIndex) {
					xmlw.writeAttribute("AssertionConsumerServiceIndex", preferredEndpoint.getIndex().toString());
				} else {
					xmlw.writeAttribute("ProtocolBinding", preferredEndpoint.getBinding());
					xmlw.writeAttribute("AssertionConsumerServiceURL", preferredEndpoint.getLocation());
				}
			}

			// Build of the issuer
			xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Issuer");
			xmlw.writeCharacters(issuer);
			xmlw.writeEndElement();

			// Add requested authentication context
			if (authnClassRef != null) {
				xmlw.writeStartElement(SamlConstants.PROTOCOL_NS, "RequestedAuthnContext");
				xmlw.writeAttribute("Comparison", authnClassComparison);

				for (String authn : authnClassRef) {
					xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "AuthnContextClassRef");
					xmlw.writeCharacters(authn);
					xmlw.writeEndElement();
				}
				xmlw.writeEndElement();

			}

			// Add subject
			if (subjectID != null) {
				xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Subject");
				xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "NameID");

				if (subjectType != null) {
					xmlw.writeAttribute("Format", subjectType);
				}

				xmlw.writeCharacters(subjectID);
				xmlw.writeEndElement();
			}

			xmlw.writeEndDocument();
			xmlw.close();

		} catch (XMLStreamException | ParserConfigurationException e) {
			throw new TechnicalException("Error when generating AuthnRequest", e);
		}

		LOG.debug("SAML authentication request generated.");

	}

	/**
	 * Get the version of the authentication request
	 *
	 * @return Version of the authentication request
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Get the destination of the authentication request
	 *
	 * @return Destination of the authentication request
	 */
	public String getDestination() {
		return destination;
	}

	/**
	 * Get the type of comparison to be used for this authentication context
	 *
	 * @return Type of comparison
	 */
	public String getAuthnContextComparison() {
		return authnClassComparison;
	}

	/**
	 * Get the authentication contexts of the authentication request
	 *
	 * @return Authentication contexts of the authentication request
	 */
	public ArrayList<String> getRequestedAuthnContext() {
		// Protect against accidental modification
		return authnClassRef == null ? null : new ArrayList<>(authnClassRef);
	}

	/**
	 * Get the issuer of the authentication request
	 *
	 * @return Issuer of the authentication request
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * Get the issue instant of the authentication request
	 *
	 * @return Issue instant of the authentication request
	 */
	public Instant getIssueInstant() {
		return issueInstant;
	}

	/**
	 * Get the user id of the authentication request
	 *
	 * @return User id of the authentication request
	 */
	public String getSubjectNameID() {
		return subjectID;
	}

	/**
	 * Get the NameId format of the authentication request
	 *
	 * @return NameId format
	 */
	public String getSubjectNameIDFormat() {
		return subjectType;
	}

	/**
	 * Get the Force Authentication attribute of the authentication request
	 *
	 * @return Force Authentication attribute of the authentication request
	 */
	public boolean isForceAuthn() {
		return forceAuthent;
	}

	/**
	 * Get the Is Passive attribute of the authentication request
	 *
	 * @return Is Passive attribute of the authentication request
	 */
	public boolean isIsPassive() {
		return passive;
	}

	/**
	 * Get the preferred ACS binding
	 *
	 * @return The preferred binding
	 */
	public Endpoint getPreferredEndPoint() {
		// Protect against accidental modification
		return preferredEndpoint == null ? null : new Endpoint(preferredEndpoint);
	}

	/**
	 * Get the preferred ACS binding
	 *
	 * @return The preferred binding
	 */
	public boolean getPreferEndpointIndex() {
		return preferEndpointIndex;
	}

	/**
	 * Displays the request in a human readable format
	 *
	 * @return Human readable form of the request
	 */
	@Override
	public String toString() {

		LOG.debug("Starting SAML Authentication Request conversion to String...");

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
			LOG.error("Error when converting AuthentRequest to String", e);
		}

		LOG.debug("SAML Authentication Request converted to String: '{}", returnValue);

		return returnValue;
	}

	/**
	 * Converts the request in base 64 format
	 *
	 * @return Request in Base 64 format
	 */
	public String toBase64() {

		LOG.debug("Starting B64 encoding of the Authentication Request...");

		String b64s = Base64.getEncoder().encodeToString(this.toString().getBytes()).replaceAll("\r", "").replaceAll("\n", "");

		LOG.debug("Authentication Request b64 encoded: '" + b64s + "'.");

		return b64s;
	}

}
