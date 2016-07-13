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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Common constants used in the SAML specification
 *  
 * @author Loeiz TANGUY
 */
public class SamlConstants {

    public static final String ASSERTION_TYPE = "assertion";
    public static final String RESPONSE_TYPE = "response";
    public static final String REQUEST_TYPE = "request";
    public static final String METADATA_TYPE = "metadata";
	
    public static final String IDENTITY_PROVIDER_TYPE = "IDP";
    public static final String SERVICE_PROVIDER_TYPE = "SP";

	public static final String ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
	public static final String PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
	public static final String METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata";
	public static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
	public static final String XML_NS = "http://www.w3.org/XML/1998/namespace";
    public static final String XML_SCHEMA_INSTANCE_NS = "http://www.w3.org/2001/XMLSchema-instance";

	public static final String UUID_PREFIX = "iio-";
	
    public static final String NAMEID_OPAQUE_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    public static final String NAMEID_OPAQUE_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    public static final String NAMEID_MAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    public static final String NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

    public static final String AUTH_PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    public static final String AUTH_TLS_CLIENT = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient";
    public static final String AUTH_MOBILE_TWO_FACTOR = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";

    public static final String SUBJECT_CONFIRMATION_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
	
    public final static String ATTRIBUTE_BASIC_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

    public final static String ATTRIBUTE_TYPE_STRING = "xs:string";
    public final static String ATTRIBUTE_TYPE_INTEGER = "xs:integer";
    public final static String ATTRIBUTE_TYPE_BOOLEAN = "xs:boolean";
    
    public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    public static final String STATUS_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Responder";
	public static final String STATUS_REQUEST_UNSUPPORTED = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";
	public static final String STATUS_NO_AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
	public static final String STATUS_REQUEST_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
	public static final String STATUS_UNSUPPORTED_BINDING = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
	
	public static final String BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	public static final String BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
	
	public static final String COMPARISON_EXACT = "exact";
	public static final String COMPARISON_MINIMUM = "minimum";
	public static final String COMPARISON_MAXIMUM = "maximum";
	public static final String COMPARISON_BETTER = "better";

	public static final String SIGNATURE_ALG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	public static final String SIGNATURE_ALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	public static final String SIGNATURE_ALG_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
	public static final String SIGNATURE_ALG_RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
	public static final String SIGNATURE_ALG_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
	public static final String SIGNATURE_ALG_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
	public static final String SIGNATURE_ALG_ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
	public static final String SIGNATURE_ALG_DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
	public static final String SIGNATURE_ALG_DSA_SHA256 = "http://www.w3.org/2009/xmldsig11#dsa-sha256";
	
	public static final String SIGNATURE_DIGEST_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
	public static final String SIGNATURE_DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
	public static final String SIGNATURE_DIGEST_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
	public static final String SIGNATURE_DIGEST_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";
	
	public static final HashMap<String, ArrayList<String>> SUPPORTED_ALGORITHMS;
	
    static
    {
    	SUPPORTED_ALGORITHMS = new HashMap<>();
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_RSA_SHA1, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA1,"SHA1withRSA")));
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_RSA_SHA256, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA256,"SHA256withRSA")));
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_RSA_SHA384, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA384,"SHA384withRSA")));
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_RSA_SHA512, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA512,"SHA512withRSA")));
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_ECDSA_SHA256, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA256,"SHA256withECDSA")));
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_ECDSA_SHA384, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA384,"SHA384withECDSA")));
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_ECDSA_SHA512, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA512,"SHA512withECDSA")));
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_DSA_SHA1, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA1,"SHA1withDSA")));
    	SUPPORTED_ALGORITHMS.put(SamlConstants.SIGNATURE_ALG_DSA_SHA256, new ArrayList<String>(Arrays.asList(SamlConstants.SIGNATURE_DIGEST_SHA256,"SHA256withDSA")));

    }
}
