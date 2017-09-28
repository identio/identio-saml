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

import net.identio.saml.exceptions.TechnicalException;
import net.identio.saml.utils.Assert;
import org.codehaus.stax2.XMLOutputFactory2;

import java.time.Instant;
import java.util.ArrayList;

/**
 * SAML assertions builder. This class must be used to generate a SAML
 * assertion.
 *
 * @author Loeiz TANGUY
 */
public class AssertionBuilder {

    private String issuer;
    private String subjectID;
    private String subjectType;
    private String subjectConfirmationMethod;
    private String subjectConfirmationInResponseTo;
    private String subjectConfirmationRecipient;
    private String authentSession;
    private String authentMethod;
    private String audience;

    private String version = "2.0";
    private int validityLength;
    private int maxTimeOffset;

    private Instant authentInstant;
    private ArrayList<Attribute> attributes;

    private static XMLOutputFactory2 xmlof;

    static {
        xmlof = (XMLOutputFactory2) XMLOutputFactory2.newInstance();

        // Configure factories
        xmlof.configureForSpeed();
    }

    protected AssertionBuilder() {
    }

    public static AssertionBuilder getInstance() {
        return new AssertionBuilder();
    }

    /**
     * Defines the issuer of the assertion
     *
     * @param issuer Name of the issuer
     * @return The current AssertionBuilder
     */
    public AssertionBuilder setIssuer(String issuer) {
        Assert.notNull(issuer, "Issuer can't be null");
        this.issuer = issuer;
        return this;
    }

    /**
     * Defines the subject of the assertion
     *
     * @param id   Identifier of the assertion
     * @param type Subject format
     * @return The current AssertionBuilder
     */
    public AssertionBuilder setSubject(String id, String type) {
        Assert.notNull(id, "Id can't be null");
        this.subjectID = id;
        this.subjectType = type;
        return this;
    }

    /**
     * Defines the usage condition of the assertion
     *
     * @param audience       Identifier of the destination
     * @param validityLength Validity period of the assertion
     * @param maxTimeOffset  Maximum time offset acceptable
     * @return The current AssertionBuilder
     */
    public AssertionBuilder setConditions(String audience, int validityLength, int maxTimeOffset) {
        this.audience = audience;
        this.maxTimeOffset = maxTimeOffset;
        this.validityLength = validityLength;
        return this;
    }

    /**
     * Defines the authentication method used
     *
     * @param authnMethod    Authentication method
     * @param authentInstant Authentication date
     * @param authentSession Authentication session identifier
     * @return The current AssertionBuilder
     */
    public AssertionBuilder setAuthentStatement(String authnMethod, Instant authentInstant, String authentSession) {
        this.authentMethod = authnMethod;
        this.authentInstant = authentInstant;
        this.authentSession = authentSession;
        return this;
    }

    /**
     * Defines the means to confirm the subject identity
     *
     * @param method       Method of confirmation
     * @param inResponseTo Identifier of the previous request
     * @param recipient    Recipient of the assertion
     * @return The current AssertionBuilder
     */
    public AssertionBuilder setSubjectConfirmation(String method, String inResponseTo, String recipient) {
        this.subjectConfirmationMethod = method;
        this.subjectConfirmationInResponseTo = inResponseTo;
        this.subjectConfirmationRecipient = recipient;
        return this;
    }

    /**
     * Set optional attributes of the assertion
     *
     * @param attributes Attribute list to add
     * @return The current AssertionBuilder
     */
    public AssertionBuilder setAttributes(ArrayList<Attribute> attributes) {
        this.attributes = new ArrayList<>(attributes);
        return this;
    }

    /**
     * Build the assertion
     *
     * @return Built assertion
     * @throws TechnicalException Thrown when something went wrong when generating the assertion
     */
    public Assertion build() throws TechnicalException {

        Assertion assertion = new Assertion();
        assertion.init(xmlof, version, issuer, subjectID, subjectType, subjectConfirmationInResponseTo,
                subjectConfirmationRecipient, subjectConfirmationMethod, authentMethod, authentInstant, authentSession,
                audience, maxTimeOffset, validityLength, attributes);

        return assertion;
    }
}
