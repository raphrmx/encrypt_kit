# 6.0.0

- Forked from `encrypt` 5.0.3 and renamed to `encrypt_plus`.
- Update to PointyCastle 4 and Dart 3.5. Remove the `crypto` dependency.
- Fix AES-GCM without padding not appending/verifying the authentication tag.
  **Breaking:** data encrypted with `AES(mode: AESMode.gcm, padding: null)` by
  older versions cannot be decrypted anymore.
- Fix `RSASigner` with `RSASignDigest.SHA512`.
- Constant-time HMAC check and token validation in `Fernet`.
- `RSASigner.verify` returns `false` on malformed signatures instead of throwing.
- `decodeHexString` throws a `FormatException` on invalid input.
- `RSAKeyParser` ignores surrounding whitespace and throws `FormatException`
  on malformed keys.
- Add `ChaCha20Poly1305` (not available on dart2js).
- Add `RSAPSSSigner`.
- Add `Key.fromPassword` (PBKDF2-HMAC-SHA256).
- Add `generateRSAKeyPair` and `RSAKeyEncoder`.
- Add `Encrypted.base64Url`.

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
