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

import org.w3c.dom.Document;

/**
 * Abstract class representing an java object that can be signed
 * 
 * @author Loeiz TANGUY
 */
public abstract class SignableSAMLObject {

	protected String id;
	protected boolean signed = false;
	protected Document doc;

    public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public boolean isSigned() {
		return signed;
	}
    
}
