/*
 * Ident.io SAML API
 * Copyright (C) 2017 Loeiz TANGUY, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */

package net.identio.saml;

import net.identio.saml.exceptions.InvalidAssertionException;
import net.identio.saml.exceptions.InvalidAuthentResponseException;
import net.identio.saml.exceptions.TechnicalException;
import org.codehaus.stax2.XMLInputFactory2;
import org.codehaus.stax2.XMLOutputFactory2;

/**
 * SAML authentication response builder. This class must be used to generate a
 * SAML response.
 *
 * @author Loeiz TANGUY
 */
public class AuthentResponseBuilder {

    private static final String version = "2.0";

    private String issuer;
    private boolean status;
    private String statusMessage;
    private String destination;
    private Assertion assertion;


    private static final XMLOutputFactory2 xmlof;
    private static final XMLInputFactory2 xmlif;

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

    protected AuthentResponseBuilder() {
    }

    public static AuthentResponseBuilder getInstance() {
        return new AuthentResponseBuilder();
    }

    /**
     * Defines the issuer of the response
     *
     * @param issuer Name of the issuer
     */
    public AuthentResponseBuilder setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Defines the status of the response
     *
     * @param status        Status of the response
     * @param statusMessage Associated status message
     */
    public AuthentResponseBuilder setStatus(boolean status, String statusMessage) {
        this.status = status;
        this.statusMessage = statusMessage;
        return this;
    }

    /**
     * Defines the destination of the response
     *
     * @param destination Destination URL
     */
    public AuthentResponseBuilder setDestination(String destination) {
        this.destination = destination;
        return this;
    }

    /**
     * Defines the assertion of the response
     *
     * @param assertion Assertion to embed in the response
     */
    public AuthentResponseBuilder setAssertion(Assertion assertion) {
        this.assertion = assertion;
        return this;
    }

    /**
     * Build a response
     *
     * @return Built response
     * @throws TechnicalException Thrown when an error occured
     */
    public AuthentResponse build() throws TechnicalException {

        AuthentResponse ar = new AuthentResponse();
        ar.init(xmlof, version, issuer, status, statusMessage, destination, assertion);
        return ar;
    }

    /**
     * Build a response from a string containing a SAML response in XML form
     *
     * @param resp String containing the response
     * @return Built response
     * @throws TechnicalException
     * @throws InvalidAuthentResponseException
     * @throws InvalidAssertionException
     */
    public AuthentResponse build(String resp)
            throws TechnicalException, InvalidAuthentResponseException {

        AuthentResponse ar = new AuthentResponse();
        ar.init(xmlif, resp);
        return ar;
    }

}
