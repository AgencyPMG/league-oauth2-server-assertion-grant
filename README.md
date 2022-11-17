# League OAuth2 Server Assertion Grant

This implements the `assertion` grants described in RFC 7521. The goal is to be
flexible enough to support JWT (RFC 7523) or SAML (RFC 7522) assertions.

https://www.rfc-editor.org/rfc/rfc7521

This was inspired by some needs that PMG's [https://www.pmg.com/alli](Alli)
platform had as well as some prior art from
[from google](https://developers.google.com/identity/protocols/oauth2/service-account).

## Client Authentication

RFCs 7523 and 7522 are opened ended about this:

```
JWT authorization grants may be used with or without client
authentication or identification.  Whether or not client
authentication is needed in conjunction with a JWT authorization
grant, as well as the supported types of client authentication, are
policy decisions at the discretion of the authorization server.
However, if client credentials are present in the request, the
authorization server MUST validate them.
```

If the `client_id` is present in the request (in the `Authorization` header of
request body), then the normal client validation methods are used. If a client
is confidential, client secret would be required.

If `client_id` is not present, then the the assertion issuer is treated as the
oauth client ID.

## Scopes

`scope` may be sent in as a normal request parameter, but RFC 7521 has this to
say:

```
The requested scope as described in Section 3.3 of
OAuth 2.0 [RFC6749].  When exchanging assertions for access
tokens, the authorization for the token has been previously
granted through some out-of-band mechanism.  As such, the
requested scope MUST be equal to or less than the scope originally
granted to the authorized accessor.  The authorization server MUST
limit the scope of the issued access token to be equal to or less
than the scope originally granted to the authorized accessor.
```

So somehow the assertion is made valid out of band. The assertion backend
returns an `Assertion` implementation which has allowed scopes.

If a caller tries to request scopes outside of the assertion's allowed scopes,
an error will be returned.

## Assertion Issuers

Assertion issuers are treated as oauth client identifiers.

## Assertion Subjects

Assertion subjects are treated as user identifiers in this library. No
accomodations for client credentials as that would be better suited for
the `client_credentials` grant with a `client_assertion` system.

