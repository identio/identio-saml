# identio-saml

[![Build Status](https://travis-ci.org/identio/identio-saml.svg?branch=master)](https://travis-ci.org/identio/identio-saml)

A developer-friendly SAML 2.0 API written in Java.

### Goal

Identio-saml is meant as a simple replacement of OpenSAML for the SAML Web Browser SSO Profile.

### Main features

  - **Very simple to use**: Much operations are done with a one-liner, even signing the SAML object, through a fluent-API.
  - **Strong performance**: The API relies where it can on XML streaming which is much faster than DOM or SAX parsing.
  - **Opiniated**: The API is based on secure defaults (for example: a security protocol message shouldn't be partially signed)
  - **Safe to use**: All builders, signers and validators are thread-safe once initialized, all SAML objects are immutable.
  
### Basic usage

##### Generate or parse a SAML AuthnRequest

The following code will generate a SAML 2.0 authentication request from scratch:

```java
ArrayList<String> reqAuthnCtx = new ArrayList<>();
reqAuthnCtx.add(SamlConstants.AUTH_PASSWORD_PROTECTED_TRANSPORT);
reqAuthnCtx.add(SamlConstants.AUTH_TLS_CLIENT);

AuthentRequest ar = AuthentRequestBuilder.getInstance().setDestination("http://idp.identio.net/SAML2")
					.setForceAuthent(false).setIsPassive(false).setIssuer("http://sp1.identio.net/sp/SAML2")
					.setRequestedAuthnContext(reqAuthnCtx, SamlConstants.COMPARISON_EXACT)
					.build();
```

Parsing a String containing a SAML AuthnRequest is straight-forward:

```java
// String containing a SAML AuthnRequest (the string is trimmed for lisibility)
String arString = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol ...";

AuthentRequest parsedAr = AuthentRequestBuilder.getInstance().build(arString, false);
```

##### Signing an AuthnRequest

The following code will sign the AuthnRequest generated in the step before:

```java
// Initialize a RSA-SHA256 signer
Signer signer = new Signer("/home/user/mykeystore.p12", "pass", false,
				SamlConstants.SIGNATURE_ALG_RSA_SHA256);
				
// Embed a XML-DSIG signature in the AuthnRequest				
signer.signEmbedded(ar);
```

### How-to add identio-saml in your project

Identio-saml package repository is provided through [JitPack](https://jitpack.io) for Gradle and Maven projects

##### Maven

1. Add the JitPack repository to your pom.xml file
```xml
<repositories>
	<repository>
		<id>jitpack.io</id>
		<url>https://jitpack.io</url>
	</repository>
</repositories>
```

2. Add the dependency
```xml
<dependency>
	<groupId>com.github.identio</groupId>
	<artifactId>identio-saml</artifactId>
	<version>1.0</version>
</dependency>
```

##### Gradle

1. Add the JitPack repository in your root build.gradle at the end of repositories:
```groovy
allprojects {
	repositories {
		...
		maven { url "https://jitpack.io" }
	}
}
```

2. Add the dependency
```groovy
dependencies {
        compile 'com.github.identio:identio-saml:1.0'
}
```