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

import net.identio.saml.common.X509KeySelector;
import net.identio.saml.exceptions.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Utility class to validate a SAML object
 *
 * @author Loeiz TANGUY
 */
public class Validator {

    // Initialize the apache security library
    static {
        org.apache.xml.security.Init.init();
    }

    private static final Logger LOG = LoggerFactory.getLogger(Validator.class);

    private ArrayList<X509Certificate> metadataCertificates;

    private final boolean certificateExpirationCheck;

    /**
     * Constructor based on list of signing certificates
     *
     * @param signingCertificates        List of certificates to validate against
     * @param certificateExpirationCheck True if the certificate expiration check should be done
     * @throws TechnicalException Thrown when something went wrong when building the Validator
     */
    public Validator(List<X509Certificate> signingCertificates, boolean certificateExpirationCheck)
            throws TechnicalException {

        LOG.debug("Starting Validator initialization...");
        LOG.debug("Is certificate expiration checked? {}", certificateExpirationCheck);

        this.certificateExpirationCheck = certificateExpirationCheck;

        metadataCertificates = new ArrayList<>();

        // Check certificate validity
        int invalidCertCount = 0;

        for (X509Certificate cert : signingCertificates) {

            try {
                if (certificateExpirationCheck) {
                    cert.checkValidity();
                }

                // If no exception is thrown, we add it to the
                // certificates to use
                metadataCertificates.add(cert);

            } catch (CertificateExpiredException e) {

                invalidCertCount++;

                LOG.error("Metadata certificate is expired", e);
            } catch (CertificateNotYetValidException e) {

                invalidCertCount++;

                LOG.error("Metadata certificate is not yet valid", e);
            }
        }

        // If all certificates are invalid, throw an exception
        if (invalidCertCount == signingCertificates.size()) {
            throw new TechnicalException("Failed to load metadata: Unable to find a valid certificate");
        }

        LOG.debug("Validator initialized.");
    }

    /**
     * Validate a SignedInfo
     *
     * @param signedInfo SignedInfo to validate
     * @param signature  Signature element
     * @param sigAlg     Signature algorithm
     * @return True if validated
     * @throws TechnicalException        Thrown when something went wrong when validating the
     *                                   signature
     * @throws InvalidSignatureException Thrown when the signature is invalid
     * @throws NoSuchAlgorithmException  Thrown when the signing algorithm is not supported
     */
    public boolean validate(String signedInfo, byte[] signature, String sigAlg)
            throws TechnicalException, InvalidSignatureException, NoSuchAlgorithmException {

        LOG.debug("Validating provided signed information...");
        LOG.debug("Signed information: {}", signedInfo);
        LOG.debug("Signature: {}", signature);
        LOG.debug("Signature Algorithm: {}", sigAlg);

        checkSignatureAlgorithm(sigAlg);

        Signature verifier;

        try {

            // We check with every known certificate
            verifier = Signature.getInstance(SamlConstants.SUPPORTED_ALGORITHMS.get(sigAlg).get(1));
            boolean validationStatus = false;
            int invalidCertCount = 0;

            for (X509Certificate cert : metadataCertificates) {

                // We check that the certificate is not expired
                if (certificateExpirationCheck) {
                    try {
                        cert.checkValidity();
                    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                        invalidCertCount++;
                        break;
                    }

                }

                verifier.initVerify(cert);
                verifier.update(signedInfo.getBytes());
                validationStatus = verifier.verify(signature);
                if (validationStatus) {
                    break;
                }

            }

            // If all certificates are invalid, throw an exception
            if (invalidCertCount == metadataCertificates.size()) {
                throw new TechnicalException("Unable to find a valid certificate in metadata");
            }

            LOG.debug("Result of the validation of the signed info: {}", validationStatus);

            return validationStatus;

        } catch (NoSuchAlgorithmException e) {
            throw new TechnicalException("Unknown signing algorithm", e);
        } catch (InvalidKeyException e) {
            throw new TechnicalException("Key is invalid", e);
        } catch (SignatureException e) {
            throw new InvalidSignatureException("Signature is invalid", e);
        }
    }

    /**
     * Validate the signature of the given SAML object.
     *
     * @param object The signed SAML object to validate.
     * @return True if validated
     * @throws UnsignedSAMLObjectException Thrown when the object is not signed
     * @throws UntrustedSignerException    Thrown if the signer is not trusted
     * @throws TechnicalException          Thrown when something went wrong when validating the
     *                                     signature
     * @throws InvalidSignatureException   Thrown when the signature is invalid
     * @throws NoSuchAlgorithmException    Thrown when the signing algorithm is not supported
     */
    public boolean validate(SignableSAMLObject object) throws UnsignedSAMLObjectException, TechnicalException,
            UntrustedSignerException, InvalidSignatureException, NoSuchAlgorithmException {

        LOG.debug("Validating provided SAML object...");
        LOG.debug("SAML object: {}", object);

        try {

            Document responseDocument = object.doc;

            // We check that the response document is made of one child
            NodeList children = responseDocument.getChildNodes();
            if (children != null && children.getLength() != 1) {
                throw new TechnicalException(
                        "Can not parse XML document: two nodes are present at the root of the document");
            }

            // We extract the ID of this element
            String id = children.item(0).getAttributes().getNamedItem("ID").getTextContent();

            NodeList docSignature = responseDocument.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

            if (docSignature.getLength() == 0) {
                throw new UnsignedSAMLObjectException("Cannot find Signature element");
            }

            // Check every signature in the document
            boolean signatureGlobal = false;
            boolean validationStatus = true;

            for (int i = 0; i < docSignature.getLength(); i++) {
                DOMValidateContext validateContext = new DOMValidateContext(new X509KeySelector(),
                        docSignature.item(i));

                validateContext.setIdAttributeNS(responseDocument.getDocumentElement(), null, "ID");

                // Force secure validation
                validateContext.setProperty("org.apache.jcp.xml.dsig.secureValidation", Boolean.TRUE);

                XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

                // Unmarshal the XMLSignature
                XMLSignature signature = fac.unmarshalXMLSignature(validateContext);

                checkSignatureAlgorithm(signature.getSignedInfo().getSignatureMethod().getAlgorithm());

                // Extract the certificate from the signature
                X509Certificate cert = extractCertificate(signature);

                // Check that the signer is trusted
                boolean signerTrusted = isSignerTrusted(cert);

                if (!signerTrusted) {
                    throw new UntrustedSignerException("Certificate is not trusted");
                }

                // Check certificate validity
                if (certificateExpirationCheck) {
                    try {
                        cert.checkValidity();

                        // If no exception is thrown, we add it to the
                        // certificates to use
                    } catch (CertificateExpiredException e) {
                        throw new TechnicalException("Certificate is expired", e);
                    } catch (CertificateNotYetValidException e) {
                        throw new TechnicalException("Certificate is not yet valid", e);
                    }
                }

                // If one signature is invalid, the whole document is invalid
                if (!signature.validate(validateContext)) {
                    throw new InvalidSignatureException("One of the signature in the document is invalid");
                }

                // We check that the signature is global and covers the entire
                // document
                if (isSignatureGlobal(signature, id)) {
                    signatureGlobal = true;
                }

                LOG.debug("Result of the validation of the SAML object: {}", validationStatus);
            }

            // If one valid signature is not global to the document, we reject it
            if (!signatureGlobal) {
                throw new InvalidSignatureException("Could not find a global signature of the document");
            }

            return true;

        } catch (MarshalException e) {
            throw new TechnicalException("Error when serializing XML", e);
        } catch (XMLSignatureException e) {
            throw new InvalidSignatureException("Invalid signature", e);
        }
    }

    /**
     * Extract X509Certificate from XMLSignature.
     *
     * @param signature
     * @return
     */
    private static X509Certificate extractCertificate(XMLSignature signature) {

        LOG.debug("Extracting certificate from XML signature...");

        X509Certificate certificate = null;

        @SuppressWarnings("rawtypes")
        Iterator ki = signature.getKeyInfo().getContent().iterator();

        while (ki.hasNext()) {
            XMLStructure info = (XMLStructure) ki.next();
            if (!(info instanceof X509Data)) {
                continue;
            }

            X509Data x509Data = (X509Data) info;
            @SuppressWarnings("rawtypes")
            Iterator xi = x509Data.getContent().iterator();

            while (xi.hasNext()) {
                Object o = xi.next();
                if (o instanceof X509Certificate) {
                    certificate = (X509Certificate) o;
                    break;
                } else {
                    continue;
                }
            }

            // Do not keep on searching if the certificate has been found
            if (certificate != null) {
                break;
            }
        }

        LOG.debug("Certificate found in XML signature: {}", certificate);

        return certificate;
    }

    /**
     * Determines if a signer is trusted or not
     *
     * @param issuerCertificate Certificate of the issuer
     * @return true if signer is trusted
     * @throws TechnicalException
     * @throws UntrustedSignerException
     */
    private boolean isSignerTrusted(X509Certificate issuerCertificate) {

        LOG.debug("Starting validation of the given issuer certificate...");
        LOG.debug("Issuer certificate: {}", issuerCertificate);

        boolean validationStatus = false;

        // We check that the certificate in the signature is in the metadata
        for (X509Certificate cert : metadataCertificates) {

            if (cert.equals(issuerCertificate)) {
                validationStatus = true;
            }

        }

        LOG.debug("Issuer certificate validation result: {}", validationStatus);

        return validationStatus;
    }

    /**
     * Determines if the signature covers all the document or not
     *
     * @param signature XML signature
     * @param rootID    Root identifier
     * @return true if the signature covers all document
     * @throws InvalidSignatureException
     */
    @SuppressWarnings("rawtypes")
    private static boolean isSignatureGlobal(XMLSignature signature, String rootID) throws InvalidSignatureException {

        LOG.debug("Starting signature globality check...");
        LOG.debug("Signature: {}", signature);
        LOG.debug("Root ID: {}", rootID);

        boolean isGlobal = false;

        // We check each Reference. One must be the rootId or be ""
        String refRootID = "#" + rootID;

        Iterator i = signature.getSignedInfo().getReferences().iterator();

        while (i.hasNext()) {
            String uri = ((Reference) i.next()).getURI();

            if ("".equals(uri) || refRootID.equals(uri)) {
                isGlobal = true;
                break;
            }

        }

        LOG.debug("Signature globality check result: {}", isGlobal);

        return isGlobal;
    }

    /**
     * Determines if the usage conditions are met
     *
     * @param assertion Assertion to check
     * @return true if all conditions are met
     * @throws InvalidAssertionException Thrown if the usage conditions of the assertion are not met
     */
    public boolean checkConditions(Assertion assertion) throws InvalidAssertionException {

        LOG.debug("Starting Assertion time conditions validation...");
        LOG.debug("Assertion: {}", assertion);

        Instant now = Instant.now();

        Instant notBefore = assertion.getNotBefore();
        Instant notOnOrAfter = assertion.getNotOnOrAfter();

        Instant notOnOrAfterSujectConfirmation = assertion.getSubjectConfirmationNotOnOrAfter();

        if (null == notBefore || null == notOnOrAfter) {
            throw new InvalidAssertionException("Assertion time validity condition missing");
        }

        if (notBefore.isAfter(now)) {
            throw new InvalidAssertionException("Assertion is not yet valid");
        }

        if (notOnOrAfter.isBefore(now) || notOnOrAfterSujectConfirmation.isBefore(now)) {
            throw new InvalidAssertionException("Assertion is expired");
        }

        LOG.debug("Assertion time validation result: Time conditions satisfied.");

        return true;
    }

    private void checkSignatureAlgorithm(String alg) throws NoSuchAlgorithmException {
        if (!SamlConstants.SUPPORTED_ALGORITHMS.containsKey(alg)) {
            throw new NoSuchAlgorithmException("Unsupported algorithm: " + alg);
        }
    }
}
