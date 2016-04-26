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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

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

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.codehaus.stax2.XMLInputFactory2;
import org.codehaus.stax2.XMLOutputFactory2;
import org.codehaus.stax2.XMLStreamReader2;
import org.codehaus.stax2.XMLStreamWriter2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import net.identio.saml.exceptions.TechnicalException;
import net.identio.saml.utils.XmlUtils;

/**
 * Represents a SAML metadata. This object can only be constructed through an
 * MetadataBuilder.
 *
 * @author Loeiz TANGUY
 */
public class Metadata extends SignableSAMLObject {

	private static final Logger LOG = LoggerFactory.getLogger(Metadata.class);

	private String entityID;
	private String organizationName;
	private String organizationDisplayName;
	private String organizationURL;
	private String contactName;
	private String contactEmail;

	private List<IdpSsoDescriptor> idpSsoDescriptors;
	private List<SpSsoDescriptor> spSsoDescriptors;

	/**
	 * Constructor from a file
	 *
	 * @param xmlif
	 *            StAX XMLInputFactory used to parse the string
	 * @param metadataFile
	 *            File containing the metadata
	 * @throws net.identio.saml.base.exceptions.TechnicalException
	 */
	protected void init(XMLInputFactory2 xmlif, File metadataFile) throws TechnicalException {

		LOG.debug("Starting Metadata generation from file: {}", metadataFile);

		try (FileInputStream fis = new FileInputStream(metadataFile);
				StringWriter writer = new StringWriter();
				InputStreamReader streamReader = new InputStreamReader(fis);
				BufferedReader buffer = new BufferedReader(streamReader)) {

			String line = "";

			while (null != (line = buffer.readLine())) {
				writer.write(line);
			}

			writer.flush();
			String metadata = writer.toString();

			if (metadataFile == null) {

				throw new TechnicalException("Parsing null Metadata file");
			}

			init(xmlif, metadata);

		} catch (IOException e) {
			throw new TechnicalException("I/O error when parsing Metadata", e);
		}

	}

	/**
	 * Constructor from a string containing a XML document
	 *
	 * @param xmlif
	 *            StAX XMLInputFactory used to parse the string
	 * @param metadata
	 *            String containing the XML document
	 * @throws net.identio.saml.base.exceptions.TechnicalException
	 */
	protected void init(XMLInputFactory2 xmlif, String metadata) throws TechnicalException {

		LOG.debug("Starting Metadata generation from metadata: {}", metadata);

		ArrayList<IdpSsoDescriptor> idpDescriptorParsed = new ArrayList<>();
		ArrayList<SpSsoDescriptor> spDescriptorParsed = new ArrayList<>();

		try {
			DocumentBuilder db = XmlUtils.getSecureDocumentBuilder();

			this.doc = db.parse(new ByteArrayInputStream(metadata.getBytes()));

			// Parse values to cache them
			XMLStreamReader2 parser = (XMLStreamReader2) xmlif
					.createXMLStreamReader(new ByteArrayInputStream(metadata.getBytes()));

			for (int event = parser.next(); event != XMLStreamConstants.END_DOCUMENT; event = parser.next()) {

				if (event != XMLStreamConstants.START_ELEMENT) {
					continue;
				}

				switch (parser.getLocalName()) {

				case "EntityDescriptor":
					entityID = parser.getAttributeValue(null, "entityID");
					id = parser.getAttributeValue(null, "ID");
					break;

				case "Signature":
					signed = true;
					break;

				case "SPSSODescriptor":
					spDescriptorParsed.add(parseSpDescriptor(parser));
					break;

				case "IDPSSODescriptor":
					idpDescriptorParsed.add(parseIdpDescriptor(parser));
					break;

				case "OrganizationName":
					organizationName = parser.getElementText();
					break;

				case "OrganizationDisplayName":
					organizationDisplayName = parser.getElementText();
					break;

				case "OrganizationURL":
					organizationURL = parser.getElementText();
					break;

				case "SurName":
					contactName = parser.getElementText();
					break;

				case "EmailAddress":
					contactEmail = parser.getElementText();
					break;
					
				default:
					// Do nothing
					break;
				}
			}

			if (idpDescriptorParsed.size() > 0) {
				this.idpSsoDescriptors = idpDescriptorParsed;
			}
			if (spDescriptorParsed.size() > 0) {
				this.spSsoDescriptors = spDescriptorParsed;
			}

			parser.close();

		} catch (SAXException | ParserConfigurationException | XMLStreamException | Base64DecodingException
				| CertificateException | NumberFormatException e) {
			throw new TechnicalException("Error when parsing Metadata", e);
		} catch (IOException e) {
			throw new TechnicalException("I/O error when parsing Metadata", e);
		}

		LOG.debug("Metadata generated.");
	}

	private List<X509Certificate> parseKeyInfo(XMLStreamReader2 parser)
			throws XMLStreamException, CertificateException, Base64DecodingException {

		ArrayList<X509Certificate> certs = new ArrayList<>();

		for (int event = parser.getEventType(); event != XMLStreamConstants.END_ELEMENT
				|| !"KeyDescriptor".equals(parser.getLocalName()); event = parser.next()) {

			// Ignore everything but a start element
			if (event != XMLStreamConstants.START_ELEMENT) {
				continue;
			}

			String localName = parser.getLocalName();

			switch (localName) {

			case "X509Certificate":

				String certString = parser.getElementText();

				CertificateFactory fact = CertificateFactory.getInstance("X.509");
				X509Certificate signingCert = (X509Certificate) fact
						.generateCertificate(new ByteArrayInputStream(Base64.decode(certString.getBytes())));
				certs.add(signingCert);
				break;
				
			default:
				// Do nothing
				break;
			}
		}

		return certs;
	}

	private IdpSsoDescriptor parseIdpDescriptor(XMLStreamReader2 parser)
			throws NumberFormatException, XMLStreamException, CertificateException, Base64DecodingException {

		IdpSsoDescriptor descriptor = new IdpSsoDescriptor();
		ArrayList<Endpoint> endpoints = new ArrayList<>();
		List<String> nameIdFormats = new ArrayList<>();

		for (int event = parser.getEventType(); event != XMLStreamConstants.END_ELEMENT
				|| !"IDPSSODescriptor".equals(parser.getLocalName()); event = parser.next()) {

			// Ignore everything but a start element
			if (event != XMLStreamConstants.START_ELEMENT) {
				continue;
			}

			String localName = parser.getLocalName();

			switch (localName) {

			case "IDPSSODescriptor":
				descriptor.setWantAuthnRequestsSigned(
						Boolean.parseBoolean(parser.getAttributeValue(null, "WantAuthnRequestsSigned")));
				break;

			case "KeyDescriptor":
				if ("signing".equals(parser.getAttributeValue(null, "use"))) {
					descriptor.setSigningCertificates(parseKeyInfo(parser));
				}
				break;

			case "SingleSignOnService":

				Endpoint endpoint = new Endpoint();

				endpoint.setBinding(parser.getAttributeValue(null, "Binding"));
				endpoint.setLocation(parser.getAttributeValue(null, "Location"));
				endpoint.setDefault(Boolean.parseBoolean(parser.getAttributeValue(null, "isDefault")));

				String indexValue = parser.getAttributeValue(null, "index");
				endpoint.setIndex(indexValue == null ? null : Integer.parseInt(indexValue));
				
				endpoints.add(endpoint);
				break;

			case "NameIDFormat":
				nameIdFormats.add(parser.getElementText());
				break;

			}
		}

		descriptor.setSsoEndpoints(endpoints);
		descriptor.setNameIDFormat(nameIdFormats);

		return descriptor;
	}

	private SpSsoDescriptor parseSpDescriptor(XMLStreamReader2 parser)
			throws XMLStreamException, CertificateException, Base64DecodingException, NumberFormatException {

		SpSsoDescriptor descriptor = new SpSsoDescriptor();
		ArrayList<Endpoint> endpoints = new ArrayList<>();
		List<String> nameIdFormats = new ArrayList<>();

		for (int event = parser.getEventType(); event != XMLStreamConstants.END_ELEMENT
				|| !"SPSSODescriptor".equals(parser.getLocalName()); event = parser.next()) {

			// Ignore everything but a start element
			if (event != XMLStreamConstants.START_ELEMENT) {
				continue;
			}

			String localName = parser.getLocalName();

			switch (localName) {

			case "SPSSODescriptor":
				descriptor.setAuthentRequestSigned(
						Boolean.parseBoolean(parser.getAttributeValue(null, "AuthnRequestsSigned")));
				descriptor.setWantAssertionsSigned(
						Boolean.parseBoolean(parser.getAttributeValue(null, "WantAssertionsSigned")));
				break;

			case "KeyDescriptor":
				if ("signing".equals(parser.getAttributeValue(null, "use"))) {
					descriptor.setSigningCertificates(parseKeyInfo(parser));
				}
				break;

			case "AssertionConsumerService":

				Endpoint endpoint = new Endpoint();

				endpoint.setBinding(parser.getAttributeValue(null, "Binding"));
				endpoint.setLocation(parser.getAttributeValue(null, "Location"));
				endpoint.setIndex(Integer.parseInt(parser.getAttributeValue(null, "index")));
				endpoint.setDefault(Boolean.parseBoolean(parser.getAttributeValue(null, "isDefault")));

				endpoints.add(endpoint);

				break;

			case "NameIDFormat":
				nameIdFormats.add(parser.getElementText());
				break;
			}
		}

		descriptor.setAssertionConsumerService(endpoints);
		descriptor.setNameIDFormat(nameIdFormats);

		return descriptor;

	}

	/**
	 * Constructor of a SP metadata from values
	 *
	 * @param xmlof
	 *            StAX XMLOutputFactory used to generate the XML
	 * @param entityID
	 *            Identifier of the IDP
	 * @param organizationName
	 *            Name of the organization
	 * @param organizationDisplayName
	 *            Display name of the organization
	 * @param orgURL
	 *            URL of the organization
	 * @param contactName
	 *            Name of principal contact
	 * @param contactEmail
	 *            E-mail address of the contact
	 * @param idpSsoDescriptors
	 *            List of IDP SSO descriptors to include
	 * @param spSsoDescriptors
	 *            List of SP SSO descriptors to include
	 * 
	 * @throws TechnicalException
	 */
	protected void init(XMLOutputFactory2 xmlof, String entityID, String organizationName,
			String organizationDisplayName, String organizationURL, String contactName, String contactEmail,
			List<IdpSsoDescriptor> idpSsoDescriptors, List<SpSsoDescriptor> spSsoDescriptors)
					throws TechnicalException {
		LOG.debug("Starting SP Metadata generation from parameters...");

		// General description of entity
		UUID uuid = UUID.randomUUID();
		this.id = SamlConstants.UUID_PREFIX + uuid.toString();

		// Cache data
		this.entityID = entityID;
		this.organizationName = organizationName;
		this.organizationDisplayName = organizationDisplayName;
		this.organizationURL = organizationURL;
		this.contactName = contactName;
		this.contactEmail = contactEmail;

		if (idpSsoDescriptors != null) {
			this.idpSsoDescriptors = new ArrayList<IdpSsoDescriptor>(idpSsoDescriptors);
		}
		if (spSsoDescriptors != null) {
			this.spSsoDescriptors = new ArrayList<SpSsoDescriptor>(spSsoDescriptors);
		}

		try {

			DocumentBuilder db = XmlUtils.getSecureDocumentBuilder();

			doc = db.newDocument();

			XMLStreamWriter2 xmlw = (XMLStreamWriter2) xmlof.createXMLStreamWriter(new DOMResult(doc));

			xmlw.writeStartDocument();
			xmlw.setPrefix("md", SamlConstants.METADATA_NS);
			xmlw.setPrefix("ds", SamlConstants.XMLDSIG_NS);
			xmlw.writeStartElement(SamlConstants.METADATA_NS, "EntityDescriptor");
			xmlw.writeNamespace("md", SamlConstants.METADATA_NS);
			xmlw.writeNamespace("ds", SamlConstants.XMLDSIG_NS);

			xmlw.writeAttribute("ID", id);
			xmlw.writeAttribute("entityID", entityID);

			// Insert IDP metadata
			if (idpSsoDescriptors != null) {
				for (IdpSsoDescriptor descriptor : idpSsoDescriptors) {
					xmlw.writeStartElement(SamlConstants.METADATA_NS, "IDPSSODescriptor");
					xmlw.writeAttribute("WantAuthnRequestsSigned",
							Boolean.toString(descriptor.isWantAuthnRequestsSigned()));
					xmlw.writeAttribute("protocolSupportEnumeration", SamlConstants.PROTOCOL_NS);

					// Insert signing certs
					ArrayList<X509Certificate> signingCerts = descriptor.getSigningCertificates();

					if (signingCerts != null) {
						for (X509Certificate cert : signingCerts) {

							xmlw.writeStartElement(SamlConstants.METADATA_NS, "KeyDescriptor");
							xmlw.writeAttribute("use", "signing");
							xmlw.writeStartElement(SamlConstants.XMLDSIG_NS, "KeyInfo");
							xmlw.writeStartElement(SamlConstants.XMLDSIG_NS, "X509Data");

							xmlw.writeStartElement(SamlConstants.XMLDSIG_NS, "X509Certificate");
							xmlw.writeCharacters(Base64.encode(cert.getEncoded()).replaceAll("\n", ""));
							xmlw.writeEndElement();
							xmlw.writeStartElement(SamlConstants.XMLDSIG_NS, "X509SubjectName");
							xmlw.writeCharacters(cert.getSubjectDN().toString());
							xmlw.writeEndElement();
							xmlw.writeEndElement();
							xmlw.writeEndElement();
							xmlw.writeEndElement();
						}
					}

					// NameID formats
					List<String> nameIdFormats = descriptor.getNameIDFormat();

					if (nameIdFormats != null) {
						for (String nameIdFormat : nameIdFormats) {
							xmlw.writeStartElement(SamlConstants.METADATA_NS, "NameIDFormat");
							xmlw.writeCharacters(nameIdFormat);
							xmlw.writeEndElement();

						}
					}

					// SSO Endpoints
					ArrayList<Endpoint> ssoEndPoints = descriptor.getSsoEndpoints();

					if (ssoEndPoints != null) {
						for (Endpoint ssoEndpoint : ssoEndPoints) {
							xmlw.writeStartElement(SamlConstants.METADATA_NS, "SingleSignOnService");
							xmlw.writeAttribute("Binding", ssoEndpoint.getBinding());
							xmlw.writeAttribute("Location", ssoEndpoint.getLocation());
							xmlw.writeEndElement();
						}
					}

					xmlw.writeEndElement();
				}
			}

			// Insert SP metadata
			if (spSsoDescriptors != null) {
				for (SpSsoDescriptor descriptor : spSsoDescriptors) {
					xmlw.writeStartElement(SamlConstants.METADATA_NS, "SPSSODescriptor");
					xmlw.writeAttribute("AuthnRequestsSigned", Boolean.toString(descriptor.isAuthentRequestSigned()));
					xmlw.writeAttribute("WantAssertionsSigned", Boolean.toString(descriptor.isWantAssertionsSigned()));
					xmlw.writeAttribute("protocolSupportEnumeration", SamlConstants.PROTOCOL_NS);

					// Insert signing certs
					ArrayList<X509Certificate> signingCerts = descriptor.getSigningCertificates();

					if (signingCerts != null) {
						for (X509Certificate cert : signingCerts) {

							xmlw.writeStartElement(SamlConstants.METADATA_NS, "KeyDescriptor");
							xmlw.writeAttribute("use", "signing");
							xmlw.writeStartElement(SamlConstants.XMLDSIG_NS, "KeyInfo");
							xmlw.writeStartElement(SamlConstants.XMLDSIG_NS, "X509Data");

							xmlw.writeStartElement(SamlConstants.XMLDSIG_NS, "X509Certificate");
							xmlw.writeCharacters(Base64.encode(cert.getEncoded()).replaceAll("\n", ""));
							xmlw.writeEndElement();
							xmlw.writeStartElement(SamlConstants.XMLDSIG_NS, "X509SubjectName");
							xmlw.writeCharacters(cert.getSubjectDN().toString());
							xmlw.writeEndElement();
							xmlw.writeEndElement();
							xmlw.writeEndElement();
							xmlw.writeEndElement();
						}
					}

					// NameID formats
					List<String> nameIdFormats = descriptor.getNameIDFormat();

					if (nameIdFormats != null) {
						for (String nameIdFormat : nameIdFormats) {
							xmlw.writeStartElement(SamlConstants.METADATA_NS, "NameIDFormat");
							xmlw.writeCharacters(nameIdFormat);
							xmlw.writeEndElement();

						}
					}

					// SSO Endpoints
					ArrayList<Endpoint> assertionConsumerServices = descriptor.getAssertionConsumerServices();

					if (assertionConsumerServices != null) {
						for (Endpoint assertionConsumerService : assertionConsumerServices) {
							xmlw.writeStartElement(SamlConstants.METADATA_NS, "AssertionConsumerService");
							xmlw.writeAttribute("Binding", assertionConsumerService.getBinding());
							xmlw.writeAttribute("Location", assertionConsumerService.getLocation());
							xmlw.writeAttribute("index", Integer.toString(assertionConsumerService.getIndex()));
							boolean isDefault = assertionConsumerService.isDefault();
							if (isDefault) {
								xmlw.writeAttribute("isDefault", "true");
							}
							xmlw.writeEndElement();
						}
					}

					xmlw.writeEndElement();
				}
			}

			xmlw.writeStartElement(SamlConstants.METADATA_NS, "Organization");
			xmlw.writeStartElement(SamlConstants.METADATA_NS, "OrganizationName");
			xmlw.writeAttribute("xml", SamlConstants.XML_NS, "lang", "en");
			xmlw.writeCharacters(organizationName);
			xmlw.writeEndElement();
			xmlw.writeStartElement(SamlConstants.METADATA_NS, "OrganizationDisplayName");
			xmlw.writeAttribute("xml", SamlConstants.XML_NS, "lang", "en");
			xmlw.writeCharacters(organizationDisplayName);
			xmlw.writeEndElement();
			xmlw.writeStartElement(SamlConstants.METADATA_NS, "OrganizationURL");
			xmlw.writeAttribute("xml", SamlConstants.XML_NS, "lang", "en");
			xmlw.writeCharacters(organizationURL);
			xmlw.writeEndElement();
			xmlw.writeEndElement();

			xmlw.writeStartElement(SamlConstants.METADATA_NS, "ContactPerson");
			xmlw.writeAttribute("contactType", "other");
			xmlw.writeStartElement(SamlConstants.METADATA_NS, "SurName");
			xmlw.writeCharacters(contactName);
			xmlw.writeEndElement();
			xmlw.writeStartElement(SamlConstants.METADATA_NS, "EmailAddress");
			xmlw.writeCharacters(contactEmail);
			xmlw.writeEndDocument();
			xmlw.close();

		} catch (ParserConfigurationException | XMLStreamException | CertificateEncodingException e) {
			throw new TechnicalException("Error when generating Metadata", e);
		}

		LOG.debug("Metadata generated.");

	}

	/**
	 * Displays the metadata in a human readable format
	 *
	 * @return Human readable form of the metadata
	 */
	@Override
	public String toString() {

		LOG.debug("Starting Metadata conversion to String...");

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
			LOG.error("Error when converting Metadata to String", e);
		}

		LOG.debug("Metadata converted to String: {}", returnValue);

		return returnValue;
	}

	/**
	 * Get the organization name
	 *
	 * @return Organization name
	 */
	public String getOrganizationName() {
		return organizationName;
	}

	/**
	 * Get the organization display name
	 *
	 * @return Organization display name
	 */
	public String getOrganizationDisplayName() {
		return organizationDisplayName;
	}

	/**
	 * Get the organization URL
	 *
	 * @return Organization URL
	 */
	public String getOrganizationURL() {
		return organizationURL;
	}

	public String getContactName() {
		return contactName;
	}

	public String getContactEmail() {
		return contactEmail;
	}

	public List<IdpSsoDescriptor> getIdpSsoDescriptors() {
		return idpSsoDescriptors;
	}

	public List<SpSsoDescriptor> getSpSsoDescriptors() {
		return spSsoDescriptors;
	}

	/**
	 * Get the entityID attribute from metadata
	 *
	 * @return entityID of metadata
	 */
	public String getEntityID() {
		return entityID;
	}
}
