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

import java.nio.charset.StandardCharsets;

import org.eclipse.jetty.util.TypeUtil;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.security.Password;

/**
 * SHA256 Credentials
 *
 * @since 0.9.67
 */
public class SHA256Credential extends Credential
{
    private static final long serialVersionUID = 1111996540822684240L;
    private static final String __TYPE = "SHA256:";

    private final byte[] _digest;

    public SHA256Credential(String digest)
    {
        digest = digest.startsWith(__TYPE) ? digest.substring(__TYPE.length()) : digest;
        _digest = TypeUtil.parseBytes(digest, 16);
    }

    public byte[] getDigest()
    {
        return _digest;
    }

    @Override
    public boolean check(Object credentials)
    {
        if (credentials instanceof char[])
            credentials=new String((char[])credentials);
        if (credentials instanceof Password || credentials instanceof String)
        {
            byte[] b = credentials.toString().getBytes(StandardCharsets.ISO_8859_1);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(b);
            byte[] digest = md.digest();
            return byteEquals(_digest, digest);
        }
        else if (credentials instanceof SHA256Credential)
        {
            SHA256Credential sha256 = (SHA256Credential)credentials;
            return byteEquals(_digest, sha256._digest);
        }
        else if (credentials instanceof Credential)
        {
            // Allow credential to attempt check - i.e. this'll work
            // for DigestAuthModule$Digest credentials
            return ((Credential)credentials).check(this);
        }
        else
        {
            //LOG.warn("Can't check " + credentials.getClass() + " against SHA256");
            return false;
        }
    }

    public String digest(String password)
    {
        byte[] b = password.getBytes(StandardCharsets.ISO_8859_1);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(b);
        byte[] digest = md.digest();
        return __TYPE + TypeUtil.toString(digest, 16);
    }

    @Override
    public String toString() {
        return "SHA256Credential: " + TypeUtil.toString(digest, 16);
    }
}
