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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.BitSet;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.security.authentication.DeferredAuthentication;
import org.eclipse.jetty.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Authentication.User;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.B64Code;
import org.eclipse.jetty.util.QuotedStringTokenizer;
import org.eclipse.jetty.util.TypeUtil;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Credential;

/**
 *  We'd like to extend DigestAuthenticator but the
 *  Digest inner class is private, so this is a wholesale copy
 *  to add multi-scheme support, and some other minor changes.
 *
 *  This supports both Digest and Basic schemes,
 *  and  both SHA-256 and MD5 Digest algorithms,
 *  all in one.
 *  Ref: RFC 7616, RFC 2617.
 *
 *  Jetty does not support multiple auth at once
 *  https://github.com/jetty/jetty.project/issues/5442
 *  but it's coming for Jetty 12.1.0
 *  https://github.com/jetty/jetty.project/pull/12393
 *  However, it's about different auth on different resources?
 *  Not multiple auth for the same resource.
 *
 *  Any scheme must be compatible with what browsers support, see
 *  RFC 7616. We adapt Jetty DigestAuthenticator to support
 *  SHA-256 and Basic while still supporting MD5.
 *  Firefox supports SHA-256 as of FF93 (2021)
 *  Chrome supports it as of Chrome 117 (2023)
 *  See chart at bottom of https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/WWW-Authenticate
 *  But Jetty still claiming there's no support in 2024
 *  and refuses to implement it: https://github.com/jetty/jetty.project/issues/11489
 *  SHA256 is still NOT supported by Safari / IOS.
 *
 *  See also SHA256Credential and MultiCredential.
 *
 *  @since 0.9.67
 */
public class MultiAuthenticator extends LoginAuthenticator
{
    private static final Logger LOG = Log.getLogger(MultiAuthenticator.class);

    private final SecureRandom _random = new SecureRandom();
    private long _maxNonceAgeMs = 60 * 1000;
    private int _maxNC = 1024;
    private final ConcurrentMap<String, Nonce> _nonceMap = new ConcurrentHashMap<>();
    private final Queue<Nonce> _nonceQueue = new ConcurrentLinkedQueue<>();
    private final boolean _enableSHA256, _enableMD5, _enableBasic;

    public MultiAuthenticator() {
        this(true, true, true);
    }

    public MultiAuthenticator(boolean enableSHA256, boolean enableMD5, boolean enableBasic)
    {
        _enableSHA256 = enableSHA256;
        _enableMD5 = enableMD5;
        _enableBasic = enableBasic;
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration)
    {
        super.setConfiguration(configuration);

        String mna = configuration.getInitParameter("maxNonceAge");
        if (mna != null)
            setMaxNonceAge(Long.valueOf(mna));
        String mnc = configuration.getInitParameter("maxNonceCount");
        if (mnc != null)
            setMaxNonceCount(Integer.valueOf(mnc));
    }

    public int getMaxNonceCount()
    {
        return _maxNC;
    }

    public void setMaxNonceCount(int maxNC)
    {
        _maxNC = maxNC;
    }

    public long getMaxNonceAge()
    {
        return _maxNonceAgeMs;
    }

    public void setMaxNonceAge(long maxNonceAgeInMillis)
    {
        _maxNonceAgeMs = maxNonceAgeInMillis;
    }

    @Override
    public String getAuthMethod()
    {
        return Constraint.__DIGEST_AUTH;
    }

    @Override
    public boolean secureResponse(ServletRequest req, ServletResponse res, boolean mandatory, User validatedUser) throws ServerAuthException
    {
        return true;
    }

    @Override
    public Authentication validateRequest(ServletRequest req, ServletResponse res, boolean mandatory) throws ServerAuthException
    {
        if (!mandatory)
            return new DeferredAuthentication(this);

        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;
        String credentials = request.getHeader(HttpHeader.AUTHORIZATION.asString());

        try
        {
            boolean stale = false;
            if (credentials != null)
            {
                if (LOG.isDebugEnabled())
                    LOG.debug("Credentials: " + credentials);
                QuotedStringTokenizer tokenizer = new QuotedStringTokenizer(credentials, "=, ", true, false);
                Digest digest = null;
                String last = null;
                String name = null;
                String scheme = null;
                String credential = null;

                while (tokenizer.hasMoreTokens())
                {
                    String tok = tokenizer.nextToken();

                    // setup based on scheme
                    if (scheme == null) {
                        scheme = tok.toLowerCase();
                        continue;
                    }
                    if (scheme.equals("digest")) {
                        if (digest == null) {
                            digest = new Digest(request.getMethod());
                        }
                    } else if (scheme.equals("basic")) {
                        // collect the space, then the credential, then break
                        if (tok.equals(" ")) {
                            // skip the space
                            continue;
                        }
                        credential = tok;
                        // processed below
                        break;
                    } else {
                        // unknown scheme
                        break;
                    }

                    char c = (tok.length() == 1) ? tok.charAt(0) : '\0';

                    switch (c)
                    {
                        case '=':
                            name = last;
                            last = tok;
                            break;
                        case ',':
                            name = null;
                            break;
                        case ' ':
                            break;

                        default:
                            last = tok;
                            if (name != null)
                            {
                                if ("username".equalsIgnoreCase(name))
                                    digest.username = tok;
                                else if ("realm".equalsIgnoreCase(name))
                                    digest.realm = tok;
                                else if ("nonce".equalsIgnoreCase(name))
                                    digest.nonce = tok;
                                else if ("nc".equalsIgnoreCase(name))
                                    digest.nc = tok;
                                else if ("cnonce".equalsIgnoreCase(name))
                                    digest.cnonce = tok;
                                else if ("qop".equalsIgnoreCase(name))
                                    digest.qop = tok;
                                else if ("uri".equalsIgnoreCase(name))
                                    digest.uri = tok;
                                else if ("response".equalsIgnoreCase(name))
                                    digest.response = tok;
                                else if ("algorithm".equalsIgnoreCase(name))
                                    digest.algorithm = tok.toLowerCase();
                                name = null;
                            }
                    }
                }

                // Now validate based on scheme type
                if ("digest".equals(scheme) &&
                    ((_enableSHA256 && digest.algorithm.equals("sha-256") ||
                     (_enableMD5 && digest.algorithm.equals("md5"))))) {
                    int n = checkNonce(digest, (Request)request);

                    if (n > 0)
                    {
                        UserIdentity user = login(digest.username, digest, req);
                        if (user != null)
                        {
                            return new UserAuthentication(Constraint.__DIGEST_AUTH, user);
                        }
                    }
                    else if (n == 0)
                        stale = true;
                } else if (_enableBasic && "basic".equals(scheme)) {
                    if (credential != null) {
                        credential = B64Code.decode(credential, StandardCharsets.ISO_8859_1);
                        int i = credential.indexOf(':');
                        if (i>0)
                        {
                            String username = credential.substring(0,i);
                            String password = credential.substring(i+1);

                            UserIdentity user = login(username, password, request);
                            if (user!=null)
                            {
                                return new UserAuthentication(Constraint.__BASIC_AUTH, user);
                            }
                        }
                    }
                } else {
                    LOG.warn("unsupported auth scheme " + scheme);
                }
            }

            if (!DeferredAuthentication.isDeferred(response))
            {
                String domain = request.getContextPath();
                if (domain == null)
                    domain = "/";
                String nonce = newNonce((Request) request);
                String realm = _loginService.getName();
                // RFC 7616 preferred first
                if (_enableSHA256) {
                    response.addHeader(HttpHeader.WWW_AUTHENTICATE.asString(), "Digest realm=\"" + realm
                        + "\", domain=\""
                        + domain
                        + "\", nonce=\""
                        + nonce
                        + "\", algorithm=SHA-256, qop=\"auth\","
                        + " stale=" + stale);
                }
                if (_enableMD5) {
                    response.addHeader(HttpHeader.WWW_AUTHENTICATE.asString(), "Digest realm=\"" + realm
                        + "\", domain=\""
                        + domain
                        + "\", nonce=\""
                        + nonce
                        + "\", algorithm=MD5, qop=\"auth\","
                        + " stale=" + stale);
                }
                if (_enableBasic) {
                    response.addHeader(HttpHeader.WWW_AUTHENTICATE.asString(), "Basic realm=\"" + realm + '"');
                }
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);

                return Authentication.SEND_CONTINUE;
            }

            return Authentication.UNAUTHENTICATED;
        }
        catch (IOException e)
        {
            throw new ServerAuthException(e);
        }
    }

    /**
     *  For digest
     */
    @Override
    public UserIdentity login(String username, Object credentials, ServletRequest request)
    {
        Digest digest = (Digest)credentials;
        if (!Objects.equals(digest.realm, _loginService.getName()))
            return null;
        return super.login(username, credentials, request);
    }

    /**
     *  For basic
     */
    public UserIdentity login(String username, String credentials, ServletRequest request)
    {
        return super.login(username, credentials, request);
    }

    public String newNonce(Request request)
    {
        Nonce nonce;

        do
        {
            byte[] nounce = new byte[24];
            _random.nextBytes(nounce);

            nonce = new Nonce(new String(B64Code.encode(nounce)), request.getTimeStamp(), getMaxNonceCount());
        }
        while (_nonceMap.putIfAbsent(nonce._nonce, nonce) != null);
        _nonceQueue.add(nonce);

        return nonce._nonce;
    }

    /**
     * @param digest  the digest data to check
     * @param request the request object
     * @return -1 for a bad nonce, 0 for a stale none, 1 for a good nonce
     */
    private int checkNonce(Digest digest, Request request)
    {
        // firstly let's expire old nonces
        long expired = request.getTimeStamp() - getMaxNonceAge();
        Nonce nonce = _nonceQueue.peek();
        while (nonce != null && nonce._ts < expired)
        {
            _nonceQueue.remove(nonce);
            _nonceMap.remove(nonce._nonce);
            nonce = _nonceQueue.peek();
        }

        // Now check the requested nonce
        try
        {
            nonce = _nonceMap.get(digest.nonce);
            if (nonce == null)
                return 0;

            long count = Long.parseLong(digest.nc, 16);
            if (count >= _maxNC)
                return 0;

            if (nonce.seen((int)count))
                return -1;

            return 1;
        }
        catch (Exception e)
        {
            LOG.ignore(e);
        }
        return -1;
    }

    private static class Nonce
    {
        final String _nonce;
        final long _ts;
        final BitSet _seen;

        public Nonce(String nonce, long ts, int size)
        {
            _nonce = nonce;
            _ts = ts;
            _seen = new BitSet(size);
        }

        public boolean seen(int count)
        {
            synchronized (this)
            {
                if (count >= _seen.size())
                    return true;
                boolean s = _seen.get(count);
                _seen.set(count);
                return s;
            }
        }
    }

    private static class Digest extends Credential
    {
        private static final long serialVersionUID = -1111639019549527724L;
        final String method;
        String username = "";
        String realm = "";
        String nonce = "";
        String nc = "";
        String cnonce = "";
        String qop = "";
        String uri = "";
        String response = "";
        // RFC 7616 default
        String algorithm = "md5";

        /* ------------------------------------------------------------ */
        Digest(String m)
        {
            method = m;
        }

        /* ------------------------------------------------------------ */
        @Override
        public boolean check(Object credentials)
        {
            if (credentials instanceof char[])
                credentials = new String((char[])credentials);
            String password = (credentials instanceof String) ? (String)credentials : credentials.toString();

            try
            {
                MessageDigest md;
                byte[] ha1 = null;
                if (algorithm.equals("sha-256")) {
                    md = MessageDigest.getInstance("SHA-256");
                    if (credentials instanceof SHA256Credential) {
                        ha1 = ((SHA256Credential)credentials).getDigest();
                    }
                } else if (algorithm.equals("md5")) {
                    md = MessageDigest.getInstance("MD5");
                    if (credentials instanceof Credential.MD5) {
                        // Credentials are already a MD5 digest - assume it's in
                        // form user:realm:password (we have no way to know since
                        // it's a digest, alright?)
                        ha1 = ((Credential.MD5)credentials).getDigest();
                    }
                } else {
                    LOG.warn("unsupported algorithm " + algorithm);
                    return false;
                }
                if (ha1 == null) {
                    // calc A1 digest
                    md.update(username.getBytes(StandardCharsets.ISO_8859_1));
                    md.update((byte)':');
                    md.update(realm.getBytes(StandardCharsets.ISO_8859_1));
                    md.update((byte)':');
                    md.update(password.getBytes(StandardCharsets.ISO_8859_1));
                    ha1 = md.digest();
                }
                // calc A2 digest
                md.reset();
                md.update(method.getBytes(StandardCharsets.ISO_8859_1));
                md.update((byte)':');
                md.update(uri.getBytes(StandardCharsets.ISO_8859_1));
                byte[] ha2 = md.digest();

                // calc digest
                // request-digest = <"> < KD ( H(A1), unq(nonce-value) ":"
                // nc-value ":" unq(cnonce-value) ":" unq(qop-value) ":" H(A2) )
                // <">
                // request-digest = <"> < KD ( H(A1), unq(nonce-value) ":" H(A2)
                // ) > <">

                md.update(TypeUtil.toString(ha1, 16).getBytes(StandardCharsets.ISO_8859_1));
                md.update((byte)':');
                md.update(nonce.getBytes(StandardCharsets.ISO_8859_1));
                md.update((byte)':');
                md.update(nc.getBytes(StandardCharsets.ISO_8859_1));
                md.update((byte)':');
                md.update(cnonce.getBytes(StandardCharsets.ISO_8859_1));
                md.update((byte)':');
                md.update(qop.getBytes(StandardCharsets.ISO_8859_1));
                md.update((byte)':');
                md.update(TypeUtil.toString(ha2, 16).getBytes(StandardCharsets.ISO_8859_1));
                byte[] digest = md.digest();

                // check digest
                return stringEquals(TypeUtil.toString(digest, 16).toLowerCase(), response == null ? null : response.toLowerCase());
            }
            catch (Exception e)
            {
                LOG.warn(e);
            }

            return false;
        }

        @Override
        public String toString()
        {
            return username + "," + response;
        }
    }
}
