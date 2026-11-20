# 6.0.0

First release of **encrypt_plus**, the maintained successor of
[`encrypt`](https://pub.dev/packages/encrypt) 5.0.3 by Leo Cavalcante.

Migrating: replace `encrypt` with `encrypt_plus` in `pubspec.yaml` and
`package:encrypt/` with `package:encrypt_plus/` in imports. The public API is
unchanged; only the behaviour changes listed under *Breaking* can affect you.

## Dependencies

- PointyCastle `^4.0.0` (was `^3.7.3`), Dart SDK `^3.5.0`.
- The `crypto` dependency is gone (HMAC now comes from PointyCastle).

## Security fixes

- **AES-GCM with `padding: null` was not authenticated**: the cipher was run
  block by block, so no tag was produced or checked and tampered cipher texts
  decrypted silently. GCM now always appends and verifies the 16 byte tag.
- Fernet compares HMACs in constant time (was a timing side channel).
- Fernet rejects truncated or malformed tokens with `StateError('Invalid
  token')` instead of a `RangeError`, before any decryption.
- `RSASigner.verify` returns `false` for any malformed signature instead of
  throwing, and compares in constant time.

## Bug fixes

- `RSASigner(RSASignDigest.SHA512)` crashed with a null check error.
- `decodeHexString` (and `Encrypted.fromBase16`) silently dropped the last
  character of an odd length input in release builds.
- `RSAKeyParser` failed on PEM strings with leading blank lines or trailing
  spaces, and reported malformed keys with assorted error types.
- AES without padding now reports a partial block with a clear
  `ArgumentError` instead of a `RangeError`.
- `ChaCha20-Poly1305` is guarded on dart2js, where PointyCastle's Poly1305 is
  unavailable, with an explicit `UnsupportedError`.

## New features

- `ChaCha20Poly1305` algorithm (RFC 8439 AEAD).
- `RSAPSSSigner` for RSA-PSS signatures (PS256 / PS512).
- `Key.fromPassword`: PBKDF2-HMAC-SHA256 key derivation (600 000 iterations
  by default, mandatory salt of at least 16 bytes).
- `generateRSAKeyPair` and `RSAKeyEncoder` (PEM export in PKCS#1 or PKCS#8).
- `Encrypted.base64Url` (Fernet tokens and JWT use URL-safe base 64).
- `package:encrypt_plus/encrypt_plus.dart` entry point (same exports as
  `encrypt.dart`).

## Breaking (behaviour only)

- Cipher texts produced by 5.x with `AES(mode: AESMode.gcm, padding: null)`
  have no tag and cannot be decrypted by 6.0.0. Decrypt them with 5.x and
  re-encrypt. All other modes and paddings produce the same bytes as 5.x.
- `decodeHexString` throws a `FormatException` on odd length input.
- `RSAKeyParser.parse` throws a `FormatException` for every malformed key.

## Quality

- The library is split into regular Dart libraries instead of `part` files.
- `very_good_analysis` lints, dartdoc on every public member.
- 86 tests (was 50), including interoperability vectors generated with the
  Python `cryptography` package, run on the VM, Chrome (dart2js) and
  WebAssembly in CI.

# 5.0.4

- Force Pointycastle version

# 5.0.3

- Fixed tests failing with AES ECB with padding by @JimWuerch in #312
- fix: Could not parse version "~3.6.2" by @Marc-R2 in #315

# 5.0.2

- Update pointycastle version to support AES-GCM with Flutter Web
- Support AES-GCM
- Fixed null safety related warnings from `package:asnlib`.

# 5.0.1

- Fix web support

# 5.0.0

- Null safety support stable (sdk: ">=2.12.0 <3.0.0")

# 5.0.0-beta.1

- Preview/prerelase null safety support

# 4.1.0

- PointyCastle v2

# 4.0.3

- Fix UTF-8 conversion on Fernet keys.

# 4.0.2

- Fix streamble AES modes without padding.

# 4.0.1

- Upgrade dependencies.

# 4.0.0

- Digital signatures signing and verification.

# 3.3.1

- Move I/O helper to another lib

# 3.3.0

- Added the Fernet algorithm, thanks to [@timfeirg](https://github.com/timfeirg)
- Moved the secure random logic to the lib
- Added key stretching

# 3.2.0

- Fix wrong casting.
- Add decryptBytes, avoids UTF-8 high coupling.
- Add public decryption and private encryption for digital signature verification.

# 3.1.0

- Add support for CRLF PEM keys.
- Fix AES without padding.
- Add `encryptBytes` method.

# 3.0.0

- Enforce IV uniqueness.

# 2.2.0

- AES padding is now optional with defaults to PKCS7.

# 2.1.0

- `secure-random` command-line tool.

# 2.0.0

- All new API

# 1.0.1

- RSA

# 1.0.0

- Stable and documented API

# 0.2.0+2

- Remove unnecessary `new`s
- Improve static typing
- Add examples index (README)

# 0.2.0+1

- Refresh dependencies, make sure it works on Dart 2
