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
package net.identio.saml.utils;

/**
 * Utility class to check user provided values
 *
 * @author Loeiz TANGUY
 */
public class Assert {

    /**
     * Check if the provided value is not null
     *
     * @param object  Object to check
     * @param message Error message to throw
     * @throws IllegalArgumentException Thrown when the provided object is null
     */
    public static void notNull(Object object, String message) throws IllegalArgumentException {

        if (object == null) {
            throw new IllegalArgumentException(message);
        }
    }

}
