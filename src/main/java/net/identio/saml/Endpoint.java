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

/**
 * Represents a SAML Endpoint, used in metadatas.
 *
 * @author Loeiz TANGUY
 */
public class Endpoint {

    private Integer index;
    private String binding;
    private String location;
    private boolean isDefault;

    public Endpoint() {
    }

    public Endpoint(Integer index, String binding, String location, boolean isDefault) {
        this.index = index;
        this.binding = binding;
        this.location = location;
        this.isDefault = isDefault;
    }

    public Endpoint(Endpoint endpoint) {
        this.index = endpoint.index;
        this.binding = endpoint.binding;
        this.location = endpoint.location;
        this.isDefault = endpoint.isDefault;
    }

    /**
     * Get the index of the endpoint in the metadatas
     *
     * @return Index of this endpoint
     */
    public Integer getIndex() {
        return index;
    }

    /**
     * Set the index of the endpoint in the metadatas
     *
     * @param index Index of this endpoint
     * @return The current Endpoint
     */
    public Endpoint setIndex(Integer index) {
        this.index = index;
        return this;
    }

    /**
     * Get the binding associated to this endpoint
     *
     * @return binding Binding of this endpoint
     */
    public String getBinding() {
        return binding;
    }

    /**
     * Set the binding associated to this endpoint
     *
     * @param binding Binding of this endpoint
     * @return The current Endpoint
     */
    public Endpoint setBinding(String binding) {
        this.binding = binding;
        return this;
    }

    /**
     * Get the location of this endpoint
     *
     * @return Endpoint location
     */
    public String getLocation() {
        return location;
    }

    /**
     * Set the location of this endpoint
     *
     * @param location Location of this endpoint
     * @return The current Endpoint
     */
    public Endpoint setLocation(String location) {
        this.location = location;
        return this;
    }

    /**
     * Defines this endpoint as the default one in the metadatas
     *
     * @param isDefault True if this endpoint should be the default
     * @return The current Endpoint
     */
    public Endpoint setDefault(boolean isDefault) {
        this.isDefault = isDefault;
        return this;
    }

    /**
     * Get if this endpoint is the default one in the metadatas
     *
     * @return True if this is the default endpoint
     */
    public boolean isDefault() {
        return isDefault;
    }
}
