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

package net.identio.saml.exceptions;

public class InvalidAssertionException extends Exception {

    private static final long serialVersionUID = 8138088844043805135L;

    public InvalidAssertionException(String s) {
        super(s);
    }

    public InvalidAssertionException(String s, Throwable e) {
        super(s, e);
    }
}
