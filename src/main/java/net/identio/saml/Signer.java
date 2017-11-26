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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Utility class to sign a SAML object
 *
 * @author Loeiz TANGUY
 */
public class Signer {

    private static final Logger LOG = LoggerFactory.getLogger(Signer.class);

    private KeyStore.PrivateKeyEntry keyEntry;
    private KeyInfo ki;

    private final String xmlSignatureMethod;
    private final String xmlDigest;
    private final String inLineSignatureMethod;

    /**
     * Build a signer
     *
     * @param keystorePath               Keystore Path
     * @param keystorePass               Keystore password
     * @param certificateExpirationCheck True if the certificate expiration check should be done
     * @param signatureMethod            Signature method to use
     * @throws TechnicalException Thrown when something went wrong when building the Signer
     */
    public Signer(String keystorePath, String keystorePass, boolean certificateExpirationCheck, String signatureMethod)
            throws TechnicalException {

        LOG.debug("Starting Signer initialization...");
        LOG.debug("Keystore path: {}", keystorePath);
        LOG.debug("Certificate expiration check: {}", certificateExpirationCheck);
        LOG.debug("Signature method: {}", signatureMethod);

        List<String> otherInformations = SamlConstants.SUPPORTED_ALGORITHMS.get(signatureMethod);

        this.xmlSignatureMethod = signatureMethod;
        this.xmlDigest = otherInformations.get(0);
        this.inLineSignatureMethod = otherInformations.get(1);

        try (FileInputStream ksFis = new FileInputStream(keystorePath)) {

            // Build a XMLSignatureFactory DOM used to generate the signature
            // enveloppe
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Load the keystore and the signature certificate
            KeyStore ks = KeyStore.getInstance("PKCS12");

            ks.load(ksFis, keystorePass.toCharArray());

            Enumeration<String> aliases = ks.aliases();

            if (aliases == null || !aliases.hasMoreElements()) {
                throw new TechnicalException("Keystore doesn't contain a certificate");
            }

            String alias = aliases.nextElement();

            keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                    new KeyStore.PasswordProtection(keystorePass.toCharArray()));
            X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

            if (certificateExpirationCheck) {
                cert.checkValidity();
            }

            // Build the KeyInfo containing the x509 datas
            KeyInfoFactory kif = fac.getKeyInfoFactory();
            List<Object> x509Content = new ArrayList<>();
            x509Content.add(cert);
            X509Data xd = kif.newX509Data(x509Content);
            ki = kif.newKeyInfo(Collections.singletonList(xd));

        } catch (CertificateExpiredException e) {
            throw new TechnicalException("Signing certificate is expired", e);
        } catch (CertificateNotYetValidException e) {
            throw new TechnicalException("Signing certificate is not yet valid", e);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new TechnicalException("Failed to load Keystore: Error when accessing idp certificate", e);
        } catch (FileNotFoundException e) {
            throw new TechnicalException("Failed to load Keystore: file " + keystorePath + " not found.", e);
        } catch (IOException e) {
            throw new TechnicalException("Failed to load Keystore: I/O error when opening " + keystorePath, e);
        } catch (UnrecoverableEntryException e) {
            throw new TechnicalException("Impossible to load idp certificate from keystore", e);
        }

        LOG.debug("Signer initialized.");
    }

    /**
     * Sign a string
     *
     * @param infoToSign A string representation of the information to sign
     * @return a signature
     * @throws TechnicalException Thrown when something went wrong when building the signature
     */
    public byte[] signExternal(String infoToSign) throws TechnicalException {

        LOG.debug("Starting object signature...");
        LOG.debug("Info To Sign: {}", infoToSign);

        Signature signer;
        byte[] signature;

        try {
            signer = Signature.getInstance(inLineSignatureMethod);

            signer.initSign(keyEntry.getPrivateKey());
            signer.update(infoToSign.getBytes());
            signature = signer.sign();

            LOG.debug("Object signed.");

        } catch (NoSuchAlgorithmException e) {
            throw new TechnicalException("Unknown signing algorithm", e);
        } catch (InvalidKeyException e) {
            throw new TechnicalException("Invalid key for signing", e);
        } catch (SignatureException e) {
            throw new TechnicalException("Error when generating signature", e);
        }

        return signature;
    }

    /**
     * Sign a SAML object
     *
     * @param object object to sign
     * @throws TechnicalException Thrown when something went wrong when building the signature
     */
    public void signEmbedded(SignableSAMLObject object) throws TechnicalException {

        LOG.debug("Starting object signature...");
        LOG.debug("SAML object: {}", object);
        LOG.debug("Id: {}", object.getId());

        try {

            // Build a XMLSignatureFactory DOM used to generate the signature
            // enveloppe
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            Element el = object.doc.getDocumentElement();

            // Build a Reference to the document enveloppe ("" URI means that
            // all the document should be signed) with SHA1 algorithm and an
            // Enveloped Transform
            Transform envelop = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);

            ArrayList<String> prefixList = new ArrayList<>();
            prefixList.add(ExcC14NParameterSpec.DEFAULT);
            prefixList.add("saml");
            if (object instanceof AuthentRequest || object instanceof AuthentResponse) {
                prefixList.add("samlp");
            }
            if (object instanceof Metadata) {
                prefixList.add("md");
            }
            prefixList.add("ds");
            prefixList.add("xs");
            prefixList.add("xsi");

            ExcC14NParameterSpec spec = new ExcC14NParameterSpec(prefixList);
            Transform c14n = fac.newTransform(CanonicalizationMethod.EXCLUSIVE, spec);
            ArrayList<Transform> transforms = new ArrayList<>();
            transforms.add(envelop);
            transforms.add(c14n);

            DigestMethod digest = fac.newDigestMethod(xmlDigest, null);

            Reference ref = fac.newReference("#" + object.getId(), digest, transforms, null, null);

            // Add the SignedInfo
            SignedInfo si = fac.newSignedInfo(
                    fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    fac.newSignatureMethod(xmlSignatureMethod, null), Collections.singletonList(ref));

            // Creation of a DOM Sign Context
            Node insertionPoint = findSignatureInsertionPoint(el);

            DOMSignContext dsc = insertionPoint == null ? new DOMSignContext(keyEntry.getPrivateKey(), el) :
                    new DOMSignContext(keyEntry.getPrivateKey(), el, insertionPoint);

            // Websphere Fix: the id is expected to be in lowercase
            dsc.setIdAttributeNS(el, null, "ID");

            // Defines signature namespace prefix
            dsc.setDefaultNamespacePrefix("ds");

            // Build the signature
            XMLSignature signature = fac.newXMLSignature(si, ki);

            // Insertion in the enveloppe
            signature.sign(dsc);

            // Set the signed flag on the object
            object.signed = true;

        } catch (NoSuchAlgorithmException e) {
            throw new TechnicalException("Unknown signing algorithm", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new TechnicalException("Invalid algorithm parameters", e);
        } catch (MarshalException e) {
            throw new TechnicalException("Error when marshaling XML document", e);
        } catch (XMLSignatureException e) {
            throw new TechnicalException("Error when signing document", e);
        }

        LOG.debug("Object signed.");
    }

    /**
     * Find the Node corresponding to the Signature Insertion Point, based on
     * SAML specifications.
     *
     * @param el Root element of the document
     * @return The Node corresponding to the Signature Insertion Point
     */
    private Node findSignatureInsertionPoint(Element el) {

        LOG.debug("Computing signature insertion point...");

        if ("EntityDescriptor".equals(el.getLocalName())) {
            return el.getFirstChild();
        }

        return el.getFirstChild().getNextSibling();
    }
}
