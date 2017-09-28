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

import java.io.IOException;
import java.io.StringWriter;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
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

import org.codehaus.stax2.XMLOutputFactory2;
import org.codehaus.stax2.XMLStreamReader2;
import org.codehaus.stax2.XMLStreamWriter2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import net.identio.saml.exceptions.InvalidAssertionException;
import net.identio.saml.exceptions.TechnicalException;
import net.identio.saml.utils.XmlUtils;

/**
 * Represents a SAML assertion. This object can only be constructed through an
 * AssertionBuilder.
 *
 * @author Loeiz TANGUY
 */
public class Assertion extends SignableSAMLObject {

    private static final Logger LOG = LoggerFactory.getLogger(Assertion.class);

    private String version;
    private String issuer;
    private String subjectID;
    private String subjectType;
    private String subjectConfirmationInResponseTo;
    private String subjectConfirmationRecipient;
    private String authentMethod;
    private Instant authentInstant;
    private String audience;
    private Instant issueInstant;
    private Instant notAfter;
    private Instant notBefore;
    private ArrayList<Attribute> attributes = new ArrayList<>();

    protected Assertion() {

    }

    /**
     * Generates a SAML Assertion using given parameters. The XML is created
     * using a XMLStreamWriter.
     *
     * @param xmlof                           XMLOutputFactory used to generate the assertion
     * @param version                         SAML version
     * @param issuer                          Issuer identifier
     * @param subjectID                       Subject identifier
     * @param subjectType                     Subject type
     * @param subjectConfirmationInResponseTo Identifier of the previous request
     * @param subjectConfirmationRecipient    Recipient of the assertion
     * @param subjectConfirmationMethod       Confirmation method of the subject identity
     * @param authentMethod                   Authentication method
     * @param authentInstant                  Authentication date
     * @param authentSession                  Identifier of the authentication session
     * @param audience                        Identifier of the destination
     * @param maxTimeOffset                   Maximum time offset acceptable
     * @param validityLength                  Validity period of the assertion
     * @param attributes                      Optional attributes
     * @throws TechnicalException
     */
    protected void init(XMLOutputFactory2 xmlof, String version, String issuer, String subjectID, String subjectType,
                        String subjectConfirmationInResponseTo, String subjectConfirmationRecipient,
                        String subjectConfirmationMethod, String authentMethod, Instant authentInstant, String authentSession,
                        String audience, int maxTimeOffset, int validityLength, ArrayList<Attribute> attributes)
            throws TechnicalException {

        LOG.debug("Starting SAML assertion generation...");

        // Cache data
        this.version = version;
        this.issuer = issuer;
        this.subjectID = subjectID;
        this.subjectType = subjectType;
        this.subjectConfirmationInResponseTo = subjectConfirmationInResponseTo;
        this.subjectConfirmationRecipient = subjectConfirmationRecipient;
        this.authentMethod = authentMethod;
        this.authentInstant = authentInstant;

        if (attributes != null) {
            this.attributes = new ArrayList<>(attributes);
        }

        this.audience = audience;

        // Update time-dependent parameters
        issueInstant = Instant.now();
        notAfter = issueInstant.plus(validityLength, ChronoUnit.MINUTES);
        notBefore = issueInstant.minus(maxTimeOffset, ChronoUnit.MINUTES);

        UUID uuid = UUID.randomUUID();
        this.id = SamlConstants.UUID_PREFIX + uuid.toString();

        // Begin init of the XML object
        try {

            XMLStreamWriter2 xmlw;

            DocumentBuilder db = XmlUtils.getSecureDocumentBuilder();
            doc = db.newDocument();

            xmlw = (XMLStreamWriter2) xmlof.createXMLStreamWriter(new DOMResult(doc));

            xmlw.writeStartDocument();
            xmlw.setPrefix("saml", SamlConstants.ASSERTION_NS);
            xmlw.setPrefix("xsi", SamlConstants.XML_SCHEMA_INSTANCE_NS);
            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Assertion");
            xmlw.writeNamespace("saml", SamlConstants.ASSERTION_NS);
            xmlw.writeNamespace("xsi", SamlConstants.XML_SCHEMA_INSTANCE_NS);

            xmlw.writeAttribute("ID", id);
            xmlw.writeAttribute("IssueInstant", issueInstant.toString());
            xmlw.writeAttribute("Version", version);

            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Issuer");
            xmlw.writeCharacters(issuer);
            xmlw.writeEndElement();

            if (subjectID != null) {
                xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Subject");
                xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "NameID");

                if (subjectType != null) {
                    xmlw.writeAttribute("Format", subjectType);
                }

                xmlw.writeCharacters(subjectID);
                xmlw.writeEndElement();
            }
            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "SubjectConfirmation");
            xmlw.writeAttribute("Method", subjectConfirmationMethod);

            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "SubjectConfirmationData");

            if (subjectConfirmationInResponseTo != null) {
                xmlw.writeAttribute("InResponseTo", subjectConfirmationInResponseTo);
            }
            if (subjectConfirmationRecipient != null) {
                xmlw.writeAttribute("Recipient", subjectConfirmationRecipient);

            }
            xmlw.writeAttribute("NotOnOrAfter", notAfter.toString());
            xmlw.writeEndElement();
            xmlw.writeEndElement();
            xmlw.writeEndElement();

            // Usage conditions
            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Conditions");
            xmlw.writeAttribute("NotBefore", notBefore.toString());
            xmlw.writeAttribute("NotOnOrAfter", notAfter.toString());

            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "AudienceRestriction");

            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Audience");
            xmlw.writeCharacters(audience);
            xmlw.writeEndElement();
            xmlw.writeEndElement();
            xmlw.writeEndElement();

            // Authentication statement
            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "AuthnStatement");
            xmlw.writeAttribute("AuthnInstant", authentInstant.toString());
            xmlw.writeAttribute("SessionIndex", authentSession);

            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "AuthnContext");

            xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "AuthnContextClassRef");
            xmlw.writeCharacters(authentMethod);
            xmlw.writeEndElement();

            xmlw.writeEndElement();
            xmlw.writeEndElement();

            // Add optional attributes
            if (attributes != null) {
                xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "AttributeStatement");

                for (Attribute attribute : attributes) {

                    xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "Attribute");
                    xmlw.writeAttribute("NameFormat", SamlConstants.ATTRIBUTE_BASIC_NAME_FORMAT);
                    xmlw.writeAttribute("Name", attribute.getName());

                    xmlw.writeStartElement(SamlConstants.ASSERTION_NS, "AttributeValue");
                    xmlw.writeAttribute("type", attribute.getType());
                    xmlw.writeCharacters(attribute.getValue());
                    xmlw.writeEndElement();

                    xmlw.writeEndElement();

                }

                xmlw.writeEndElement();
            }

            xmlw.writeEndDocument();
            xmlw.close();

        } catch (XMLStreamException | ParserConfigurationException e) {
            throw new TechnicalException("Error when generating Assertion", e);
        }

        LOG.debug("SAML assertion generated.");
    }

    /**
     * Generates a SAML Assertion using a given XMLStreamReader and a SAML
     * assertion.
     *
     * @param parser       XMLStreamReader used to parse the document
     * @param assertionDoc Assertion DOM document
     * @throws TechnicalException
     * @throws InvalidAssertionException
     */
    protected void init(XMLStreamReader2 parser, Document assertionDoc)
            throws TechnicalException, InvalidAssertionException {

        LOG.debug("Starting SAML assertion generation...");

        doc = assertionDoc;

        try {

            for (int event = parser.getEventType(); event != XMLStreamConstants.END_ELEMENT
                    || !"Assertion".equals(parser.getLocalName()); event = parser.next()) {

                // Ignore everything but a start element
                if (event != XMLStreamConstants.START_ELEMENT) {
                    continue;
                }

                String localName = parser.getLocalName();

                switch (localName) {

                    case "Assertion":
                        version = parser.getAttributeValue(null, "Version");
                        id = parser.getAttributeValue(null, "ID");
                        issueInstant = Instant.parse(parser.getAttributeValue(null, "IssueInstant"));
                        break;

                    case "Signature":
                        signed = true;
                        break;

                    case "Issuer":
                        issuer = parser.getElementText();
                        break;

                    case "Audience":
                        audience = parser.getElementText();
                        break;

                    case "AuthnContextClassRef":
                        authentMethod = parser.getElementText();
                        break;

                    case "NameID":
                        subjectType = parser.getAttributeValue(null, "Format");
                        subjectID = parser.getElementText();
                        break;

                    case "Conditions":
                        notBefore = Instant.parse(parser.getAttributeValue(null, "NotBefore"));
                        notAfter = Instant.parse(parser.getAttributeValue(null, "NotOnOrAfter"));
                        break;

                    case "AuthnStatement":
                        authentInstant = Instant.parse(parser.getAttributeValue(null, "AuthnInstant"));
                        break;

                    case "SubjectConfirmationData":
                        subjectConfirmationInResponseTo = parser.getAttributeValue(null, "InResponseTo");
                        subjectConfirmationRecipient = parser.getAttributeValue(null, "Recipient");
                        break;

                    case "Attribute":
                        if (attributes == null) {
                            attributes = new ArrayList<>();
                        }

                        String name = null;
                        String type = null;
                        String value = null;

                        name = parser.getAttributeValue(null, "Name");

                        parser.nextTag();

                        if ("AttributeValue".equals(parser.getLocalName())) {
                            type = parser.getAttributeValue(null, "type");
                            value = parser.getElementText();
                        }

                        attributes.add(new Attribute(name, type, value));

                        break;

                    default:
                        // Do nothing
                        break;
                }
            }

        } catch (XMLStreamException e) {
            throw new TechnicalException("Error when parsing Assertion", e);
        }

        LOG.debug("SAML assertion generated.");
    }

    /**
     * Displays the assertion in a human readable format
     *
     * @return Human readable form of the assertion
     */
    @Override
    public String toString() {

        LOG.debug("Starting SAML assertion conversion to String...");

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
            LOG.error("Error when converting SAML Assertion to String", e);
        }

        LOG.debug("SAML assertion converted to String: '{}'", returnValue);

        return returnValue;
    }

    /**
     * Get the ID of the assertion
     *
     * @return ID of the assertion
     */
    public String getID() {
        return id;
    }

    /**
     * Get the ID of the previous authentication request
     *
     * @return ID of the previous authentication request
     */
    public String getInResponseTo() {
        return subjectConfirmationInResponseTo;
    }

    /**
     * Get the recipient of the assertion
     *
     * @return Recipient of the assertion
     */
    public String getRecipient() {
        return subjectConfirmationRecipient;
    }

    /**
     * Get the maximum validity date of the assertion
     *
     * @return Maximum validity date of the assertion
     */
    public Instant getSubjectConfirmationNotOnOrAfter() {
        return notAfter;
    }

    /**
     * Get the issuer of the assertion
     *
     * @return Issuer of the assertion
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Get the generation date of the assertion
     *
     * @return Generation date of the assertion
     */
    public Instant getIssueInstant() {
        return issueInstant;
    }

    /**
     * Get the version of the assertion
     *
     * @return Version of the assertion
     */
    public String getVersion() {
        return version;
    }

    /**
     * Get the user Id embedded in the assertion
     *
     * @return User Id
     */
    public String getSubjectNameID() {
        return subjectID;
    }

    /**
     * Get the date when the user was authenticated
     *
     * @return Date when the user was authenticated
     */
    public Instant getAuthnInstant() {
        return authentInstant;
    }

    /**
     * Get the format of the user Id
     *
     * @return Format of the user Id
     */
    public String getSubjectNameIDFormat() {
        return subjectType;
    }

    /**
     * Get the minimum validity date of the assertion
     *
     * @return Minimum validity date of the assertion
     */
    public Instant getNotBefore() {
        return notBefore;
    }

    /**
     * Get the maximum validity date of the assertion
     *
     * @return Maximum validity date of the assertion
     */
    public Instant getNotOnOrAfter() {
        return notAfter;
    }

    /**
     * Get the audience of the assertion
     *
     * @return Audience of the assertion
     */
    public String getAudienceRestriction() {
        return audience;
    }

    /**
     * Get the authentication context of the assertion
     *
     * @return Authentication context of the assertion
     */
    public String getAuthnContext() {
        return authentMethod;
    }

    /**
     * Get the optional attributes of the assertion
     *
     * @return Attributes of the assertion
     */
    public ArrayList<Attribute> getAttributes() {

        if (attributes != null) {
            return new ArrayList<>(attributes);
        }

        return null;
    }
}
