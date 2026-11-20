# Security audit of `encrypt` 5.0.4

Audit performed in November 2026 when forking
[`encrypt`](https://github.com/leocavalcante/encrypt) (last commit
`ec0c1fc`, June 2025) into `encrypt_plus`. Every finding below was reproduced
with a test before being fixed; the regression tests live in
[`test/security_fixes_test.dart`](test/security_fixes_test.dart).

| # | Severity | Component | Finding | Status in 6.0.0 |
| --- | --- | --- | --- | --- |
| 1 | High | `AES` (GCM) | With `padding: null`, GCM was run block by block through `processBlock`: no tag was appended on encryption and none was checked on decryption. A modified cipher text decrypted to modified plain text without error. | Fixed: GCM always goes through `process`, 16 byte tag appended and verified. |
| 2 | Medium | `Fernet` | The HMAC was compared with `ListEquality`, which returns at the first different byte (timing side channel usable to forge a MAC byte by byte). | Fixed: constant-time comparison. |
| 3 | Medium | `Fernet` | Tokens shorter than the fixed header or with a cipher text that is not a whole number of blocks crashed with `RangeError` / reached the AES decryption. | Fixed: structure validated first, `StateError('Invalid token')`. |
| 4 | Medium | `RSASigner` | `RSASignDigest.SHA512` was declared but missing from the digest table: the constructor crashed with a null check error. | Fixed, SHA-512 DigestInfo added, checked against Python `cryptography`. |
| 5 | Low | `RSASigner.verify` | Only `ArgumentError` was caught: other malformed signatures could throw instead of returning `false`. The main comparison was not constant time. | Fixed. |
| 6 | Low | `decodeHexString` | The even-length check was an `assert`, so release builds silently dropped the last character of odd-length input. | Fixed: `FormatException`. |
| 7 | Low | `Key.stretch` | PBKDF2-HMAC-SHA1 with 100 iterations by default; without an explicit salt, a random salt is generated and lost, so the derived key cannot be re-derived. | Kept for compatibility, documented; `Key.fromPassword` (PBKDF2-HMAC-SHA256, 600 000 iterations, mandatory 16+ byte salt) added. |
| 8 | Info | `AES` defaults | Default mode is SIC/CTR with PKCS7 padding (unauthenticated); ECB is available. | Kept for compatibility; documentation points to GCM / ChaCha20-Poly1305. |
| 9 | Info | `RSA` defaults | PKCS#1 v1.5 encryption and OAEP-SHA1 by default. | Kept for compatibility; OAEP-SHA256 recommended in docs. |
| 10 | Info | `Encrypter.decrypt` | UTF-8 decoding uses `allowMalformed: true`, so a wrong key in an unauthenticated mode returns garbage instead of failing. | Kept for compatibility, documented. |
| 11 | Info | Dependencies | Pinned to PointyCastle 3.x, unmaintained for 3 years. | Upgraded to PointyCastle 4. |

## Found in PointyCastle 4.0.0 (worked around)

- `ChaCha20Poly1305.process` never calls `doFinal`: the output has no tag
  and is all zeros for short inputs. `encrypt_plus` drives
  `processBytes` + `doFinal` itself.
- `ChaCha20Poly1305.getUpdateOutputSize` has no `return` statement.
- A bad Poly1305 tag is reported as an `ArgumentError`; `encrypt_plus` turns
  it into an `InvalidCipherTextException`, like AES-GCM.
- Poly1305 is unavailable when compiled to JavaScript; `encrypt_plus`
  throws an explicit `UnsupportedError` (`ChaCha20Poly1305.isSupported`).

## Verification

- All 50 original tests pass unchanged (only the import changed), so every
  vector produced by 5.x is still produced by 6.0.0, except the GCM/no padding
  case above.
- Interoperability vectors generated with the Python `cryptography` package
  (AES-GCM, ChaCha20-Poly1305, PBKDF2, Fernet, RS512, PS256); Dart generated
  keys, PSS signatures, OAEP cipher texts and Fernet tokens were also checked
  with Python.
- Tests run on the Dart VM, Chrome (dart2js) and Chrome (dart2wasm).
