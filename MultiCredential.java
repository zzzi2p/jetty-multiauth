//
//  ========================================================================
//  Copyright (c) 1995-2020 Mort Bay Consulting Pty Ltd and others.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package net.i2p.jetty;

import java.util.List;

import org.eclipse.jetty.util.security.Credential;

/**
 * Multiple Credentials
 *
 * @since 0.9.67
 */
public class MultiCredential extends Credential
{
    private static final long serialVersionUID = 1133333330822684240L;

    private final List<Credential> creds;

    /**
     * @param credentials will be checked in-order
     */
    public MultiCredential(List<Credential> credentials)
    {
        creds = credentials;
    }

    @Override
    public boolean check(Object credentials)
    {
        for (Credential cred : creds) {
            if (cred.check(credentials))
                return true;
        }
        return false;
    }

    @Override
    public String toString() {
        return "MultiCredential: " + creds.toString();
    }
}
