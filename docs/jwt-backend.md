# JWT Assertions

As described in RFC 7523: https://www.rfc-editor.org/rfc/rfc7523

Grant type is `urn:ietf:params:oauth:grant-type:jwt-bearer`

## Protocol

The best gist here is that a client will send a request to an authorization
server's token endpoint with...

```
POST https://idp.com/token

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion={JWT_HERE}
```

The JWT _should_ be signed with an asymetric key. The authorization server (eg.
this library) will have the public key and can verify the the signature and
then verify the assertion itself.

Other, simple keys (like hmac with a shared secret) are possible as well.

Requests _may_ include client credentials (`client_id`, `client_secret`, and
`redirect_uri`). Including these will trigger normal client validation and the
issuer of the token will be expected to match the `client_id`.

### JWT Headers

- `typ` (optional), but should be `JWT`
- `alg` (required) this will be the choice of the client of this library, pass
  the correct signer to grant when creating it.
- `kid` (required) the key id that was used to sign the JWT

### JWT Claims

These are laid out in RFC7523, but the specifics here:

- `iss` (required) the ID of oauth client that is making the assertion request,
  the issued token will be associated with this oauth client. This _must_ match
  the `client_id` in the request.
- `sub` (required) the ID of the user to which the token will be issued.
- `aud` (required) the agreed upon audience between the client and authorization
  server. This could be the auth server's domain (eg `https://auth.example.com`)
  or a token endpoint (`https://example.com/auth/token`).
- `exp` (required) when the assertion expires. This cannot be further in the
  future than the access token TTL for the grant.
- `iat` and `nbf` (optional) when the assertion was issued and when it can first
  be used respectively.
- `jti` (optional, see "preventing replays" below) The unique identifier of the
  assertion.

### Signatures

The authorization server (this library) will look up the appropriate key based
on the `kid` (key ID) header and validate the signature of the JWT before
validating any further claims.

How the key works is largely up to the the user.

This library used `lcobucci/jwt` and takes a signer instance to the grants
constructor.

## Usage

### AssertionKey

Users of this library must implement `PMG\AssertionGrant\Jwt\AssertionKey`.

This represent the single key, looked up by `AssertionKeyRepositoryInterface`.
There are some typical getters here: `getIdentifier` and `getSigningKey`.

Assertion keys are generally created "out of band" to this library. So when they
are created, the scopes of the original authentication method (eg another OAuth
Access Token) should be stored alongside the key.

Additionally the `AssertionKey` has a method to check whether the assertions
issuer and subject are allowed. This could be used to check that the key was
created by the given subject (user) and with the given issuer (oauth client).

### AssertionKeyRepository

Only a single method here get a key entity by its ID:
`AssertionKeyRepository::getAssertionKeyEntity(string $keyId)`.

### AssertionRepository (Preventing Replay Attacks)

This one is meant to prevent replay attacks if desired.

Implement this to check and store `jti` values,
`AssertionRepository::isAssertionReplay` should return true if the 
`jti` value passed has already been seen and `persistNewAssertion(string $jti)`
should store a JTI value to track later.

### Setup

#### Minimal Example

The only _required_ implementation is of `AssertionKey` and
`AssertionKeyRepository`. This will use a RSA SHA 384 signer.

```php
use League\OAuth2\Server\AuthorizationServer;
use PMG\AssertionGrant\AssertionGrant;
use PMG\AssertionGrant\Jwt\AssertionKeyRepository;
use PMG\AssertionGrant\Jwt\JwtAssertionGrantBackend;

const AUDIENCE = 'https://yourapp.com/token';

$assertionKeyRepo = new YourAssertionKeyRepo();
assert($assertionKeyRepo instanceof AssertionKeyRepistory);

$backend = new JwtAssertionGrantBackend($assertionKeyRepo);

$grant = new AssertionGrant($backend, AUDIENCE);

/** @var AuthorizationSever $server */
$server->enableGrantType($grant);
```

### Full Example


```php
use League\OAuth2\Server\AuthorizationServer;
use Lcobucci\Jwt\Signer\Rsa\Sha512;
use PMG\AssertionGrant\AssertionGrant;
use PMG\AssertionGrant\Jwt\AssertionRepository;
use PMG\AssertionGrant\Jwt\AssertionKeyRepository;
use PMG\AssertionGrant\Jwt\JwtAssertionGrantBackend;

const AUDIENCE = 'https://yourapp.com/token';

$assertionKeyRepo = new YourAssertionKeyRepo();
assert($assertionKeyRepo instanceof AssertionKeyRepistory);

$assertionRepo = new YourAssertionRepo();
assert($assertionRepo instanceof AssertionRepository);

$backend = new JwtAssertionGrantBackend(
    $assertionKeyRepo,
    new Sha512(),
    $assertionRepo
);

$grant = new AssertionGrant($backend, AUDIENCE);

/** @var AuthorizationSever $server */
$server->enableGrantType($grant);
```

### Client Side

Example here with `lcobucci/jwt`, but the gist of this is that clients using
these assertions will need to know...

1. What algorithm to use for token signatures
1. The key with which to sign the signature
1. The key ID of the key in the authorization (this happens "out of band": so this
   library does not have any say in the key IDs, only that they are strings).
1. The audience the assertion is intended for
1. The oauth client ID that the issued token will be associated with
1. A user ID of the user that the issued token will be associated with

```php
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Lcobucci\Jwt\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use Lcobucci\JWT\Signer\Key\InMemory;

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const TOKEN_ENDPOINT = 'https://example.com/token';
const KEY_ID = 'some-key-id-here';
const OAUTH_CLIENT_ID = 'some-client-id-here';
const USER_ID = 'some-user-id-here';

$jwtConfig = Configuration::forAsymmetricSigner(
    new Sha512(),
    InMemory::file('path_to_private_key.pem'),
    InMemory::plainText('ignored: we aren't validating signatures')
);

$expires = (new DateTimeImmutable())->add(new DateInterval('PT10M'));

$assertion = $jwtConfig->builder()
    ->withHeader('kid', KEY_ID)
    ->expiresAt($expires)
    ->permittedFor(TOKEN_ENDPOINT)
    ->issuedBy(OAUTH_CLIENT_ID)
    ->relatedTo(USER_ID)
    ->identifiedBy(bin2hex(randome_bytes(16))) // optional, this just needs to be sufficiently unique
    ->getToken(
        $this->jwtConfig->signer(),
        $this->jwtConfig->signingKey()
    ); 

$client = new Client();

$response = $client->request('POST',TOKEN_ENDPOINT, [
    RequestOptions::FORM_PARAMS => [
        'grant_type' => GRANT_TYPE,
        'assertion' => $assertion->toString(),
    ],
]);
$body = json_decode($response->getBody());
var_dump($body); // will have access_token, token_type, expires_in
```
