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

import net.identio.saml.exceptions.TechnicalException;
import net.identio.saml.utils.Assert;
import org.codehaus.stax2.XMLInputFactory2;
import org.codehaus.stax2.XMLOutputFactory2;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * SAML metadata builder. This class must be used to generate a SAML metadata.
 *
 * @author Loeiz TANGUY
 */
public class MetadataBuilder {

    private String entityID;
    private String organizationName;
    private String organizationDisplayName;
    private String organizationURL;
    private String contactName;
    private String contactEmail;

    private List<IdpSsoDescriptor> idpSsoDescriptors;
    private List<SpSsoDescriptor> spSsoDescriptors;

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

    protected MetadataBuilder() {
    }

    public static MetadataBuilder getInstance() {
        return new MetadataBuilder();
    }

    public MetadataBuilder setEntityID(String entityID) {
        this.entityID = entityID;
        return this;
    }

    public MetadataBuilder setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
        return this;
    }

    public MetadataBuilder setOrganizationDisplayName(String organizationDisplayName) {
        this.organizationDisplayName = organizationDisplayName;
        return this;
    }

    public MetadataBuilder setOrganizationURL(String organizationURL) {
        this.organizationURL = organizationURL;
        return this;
    }

    public MetadataBuilder setContactName(String contactName) {
        this.contactName = contactName;
        return this;
    }

    public MetadataBuilder setContactEmail(String contactEmail) {
        this.contactEmail = contactEmail;
        return this;
    }

    public MetadataBuilder setIdpSsoDescriptors(List<IdpSsoDescriptor> idpSsoDescriptors) {
        Assert.notNull(idpSsoDescriptors, "IDP descriptors can't be null.");
        this.idpSsoDescriptors = new ArrayList<>(idpSsoDescriptors);
        return this;
    }

    public MetadataBuilder setSpSsoDescriptors(List<SpSsoDescriptor> spSsoDescriptors) {
        Assert.notNull(spSsoDescriptors, "SP descriptors can't be null.");
        this.spSsoDescriptors = new ArrayList<>(spSsoDescriptors);
        return this;
    }

    /**
     * Build the metadata
     *
     * @return Built metadata
     * @throws TechnicalException Thrown when something went wrong when building the metadata
     */
    public Metadata build() throws TechnicalException {

        Metadata metadata = new Metadata();

        metadata.init(xmlof, entityID, organizationName, organizationDisplayName, organizationURL, contactName,
                contactEmail, idpSsoDescriptors, spSsoDescriptors);

        return metadata;
    }

    /**
     * Build a metadata from a XML file
     *
     * @param file Source XML file
     * @return Built metadata
     * @throws TechnicalException Thrown when something went wrong when building the metadata
     */
    public static Metadata build(File file) throws TechnicalException {

        Metadata metadata;
        String filepath = "";

        try {

            metadata = new Metadata();

            if (file != null) {
                filepath = file.getCanonicalPath();
            }

            metadata.init(xmlif, file);
        } catch (IOException | TechnicalException e) {
            throw new TechnicalException("Error while building metadata from file: " + filepath, e);
        }
        return metadata;
    }

    /**
     * Build a metadata from a string containing a XML document
     *
     * @param xmlData String containing the XML document
     * @return Built metadata
     * @throws TechnicalException Thrown when something went wrong when building the metadata
     */
    public static Metadata build(String xmlData) throws TechnicalException {

        Metadata metadata;

        try {

            metadata = new Metadata();

            if (xmlData != null) {
                metadata.init(xmlif, xmlData);
            }
        } catch (Exception e) {
            throw new TechnicalException("Error while building metadata from string: " + xmlData, e);
        }

        return metadata;
    }
}
