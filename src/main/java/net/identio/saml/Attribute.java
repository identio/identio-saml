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

import java.io.Serializable;

/**
 * Represents a SAML basic attribute.
 *
 * @author Loeiz TANGUY
 */
public class Attribute implements Serializable {

    private static final long serialVersionUID = 1244964576145910653L;

    private final String name;
    private final String type;
    private final String value;

    /**
     * Get the name of the attribute
     *
     * @return Name of the attribute
     */
    public String getName() {
        return name;
    }

    /**
     * Get the type of the attribute
     *
     * @return Type of the attribute
     */
    public String getType() {
        return type;
    }

    /**
     * Get the value of the attribute
     *
     * @return Value of the attribute
     */
    public String getValue() {
        return value;
    }

    /**
     * Constructor of an attribute with a friendly name and a value.
     * The generated attribute is implicitly of type String
     *
     * @param friendlyName Friendly name of the attribute
     * @param value        Value of the attribute
     */
    public Attribute(String friendlyName, String value) {
        name = friendlyName;
        type = "xs:string";
        this.value = value;
    }

    /**
     * Constructor of an attribute with a name, a type and a value.
     *
     * @param name  Name of the attribute
     * @param type  Type of the attribute
     * @param value Value of the attribute
     */
    public Attribute(String name, String type, String value) {
        this.name = name;
        this.type = type;
        this.value = value;
    }

    /**
     * Constructor of an attribute with a name, a type and a value.
     * The type is infered from the class of value. Only String, Integer and
     * Boolean are supported.
     * All other types will be considered as String.
     *
     * @param name  Name of the attribute
     * @param value Value of the attribute
     */
    public Attribute(String name, Object value) {
        if (value instanceof Integer) {
            this.type = SamlConstants.ATTRIBUTE_TYPE_INTEGER;
            this.value = ((Integer) value).toString();
        } else if (value instanceof Boolean) {
            this.type = SamlConstants.ATTRIBUTE_TYPE_BOOLEAN;
            this.value = ((Boolean) value).toString();
        } else {
            this.type = SamlConstants.ATTRIBUTE_TYPE_STRING;
            this.value = value.toString();
        }
        this.name = name;
    }
}
