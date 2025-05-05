Support for SHA-256 Digest Authentication and
simultaneous authentication for SHA-256 Digest, MD5 Digest, and Basic.
For Jetty 9.3 / 9.4, may need changes for later versions.

Use SHA256Credential for SHA-256.
Use MultiCredential for multiple types.

Usage:

Use MultiAuthenticator instead of Jetty's DigestAuthenticator or BasicAuthenticator.
Use MultiCredential or SHA256Credential instead of
or in addition to Jetty's Credential.MD5 or Password.

Adapted from Jetty 9.3.29 DigestAuthenticator.
Copyright (c) 1995-2020 Mort Bay Consulting Pty Ltd and others.
Apache 2.0 license

Note:

This is different from the MultiAuthenticator in this Jetty 12.1 PR:
https://github.com/jetty/jetty.project/pull/12393

That Jetty PR supports different authenticators for different path specs.
This code supports multiple authentication types on all paths.
If that PR gets merged, you may want to rename this class.
