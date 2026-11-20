# encrypt_plus

[![pub package](https://img.shields.io/pub/v/encrypt_plus.svg)](https://pub.dev/packages/encrypt_plus)
[![CI](https://github.com/raphrmx/encrypt_plus/actions/workflows/ci.yml/badge.svg)](https://github.com/raphrmx/encrypt_plus/actions/workflows/ci.yml)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

High-level APIs over [PointyCastle](https://pub.dev/packages/pointycastle) for
two-way cryptography: AES, ChaCha20-Poly1305, RSA, Salsa20, Fernet, RSA
signatures and password based keys.

**encrypt_plus is the maintained, audited successor of
[`encrypt`](https://pub.dev/packages/encrypt)** by Leo Cavalcante, which is
archived and stuck on PointyCastle 3. It keeps the same API, runs on
PointyCastle 4, fixes the security issues found during an audit, and adds
modern algorithms.

## Migrating from `encrypt`

```yaml
dependencies:
  encrypt_plus: ^6.0.0
```

```dart
// Before
import 'package:encrypt/encrypt.dart';
// After
import 'package:encrypt_plus/encrypt.dart';
```

That is all for almost every project. Read the [CHANGELOG](CHANGELOG.md) for
the three behaviour changes (the main one: AES-GCM with `padding: null` is now
authenticated, as it always should have been).

## Which algorithm should I use?

| Need | Use |
| --- | --- |
| Encrypt data with a random key | `AES(key, mode: AESMode.gcm)` or `ChaCha20Poly1305(key)` |
| Encrypt data with a password | `Key.fromPassword` + AES-GCM |
| Exchange tokens with Python | `Fernet` |
| Encrypt for someone else's public key | `RSA` with `RSAEncoding.OAEP` (small payloads, or wrap an AES key) |
| Sign / verify | `RSAPSSSigner` (or `RSASigner` for PKCS#1 v1.5 / RS256) |

Prefer **authenticated** modes (AES-GCM, ChaCha20-Poly1305, Fernet): the other
AES modes and Salsa20 do not detect tampering or a wrong key. Never reuse an
IV / nonce with the same key.

## Symmetric encryption

### AES-GCM

```dart
import 'package:encrypt_plus/encrypt.dart';

void main() {
  final key = Key.fromSecureRandom(32);
  final iv = IV.fromSecureRandom(12); // new for every message
  final encrypter = Encrypter(AES(key, mode: AESMode.gcm));

  final encrypted = encrypter.encrypt('Lorem ipsum', iv: iv);
  final decrypted = encrypter.decrypt(encrypted, iv: iv);
}
```

Optional `associatedData` is authenticated but not encrypted. A tampered
cipher text, wrong key, IV or associated data throws an
`InvalidCipherTextException`.

#### Other modes

`AES(key, mode: ...)` also supports `cbc`, `cfb64`, `ctr`, `ecb`, `ofb64`,
`ofb64Gctr` and `sic` (the default, for compatibility). Pass `padding: null`
to disable PKCS7 padding.

### ChaCha20-Poly1305

```dart
final encrypter = Encrypter(ChaCha20Poly1305(Key.fromSecureRandom(32)));
final nonce = IV.fromSecureRandom(12);
final encrypted = encrypter.encrypt('Lorem ipsum', iv: nonce);
```

Available on the VM, Flutter native and WebAssembly. Not available when the
web app is compiled to JavaScript (`ChaCha20Poly1305.isSupported`).

### Key from a password

```dart
final salt = SecureRandom(16).bytes; // store it with the cipher text
final key = Key.fromPassword('correct horse battery staple', salt: salt);
```

PBKDF2-HMAC-SHA256 with 600 000 iterations by default (OWASP). It is slow on
purpose: run it outside of the UI isolate when you can.

### Fernet

[Fernet](https://github.com/fernet/spec/blob/master/Spec.md) tokens are
compatible with Python's `cryptography.fernet`.

```dart
final fernet = Fernet(Key.fromBase64(urlSafeBase64Key));
final token = Encrypter(fernet).encrypt('Lorem ipsum').base64Url;
final plain = fernet.decrypt(Encrypted.fromBase64(token), ttl: 3600);
```

### Salsa20

```dart
final encrypter = Encrypter(Salsa20(Key.fromSecureRandom(32)));
final iv = IV.fromSecureRandom(8);
final encrypted = encrypter.encrypt('Lorem ipsum', iv: iv);
```

## RSA

### Keys

```dart
import 'package:encrypt_plus/encrypt.dart';
import 'package:encrypt_plus/encrypt_io.dart'; // VM / Flutter native only
import 'package:pointycastle/asymmetric/api.dart';

final publicKey = await parseKeyFromFile<RSAPublicKey>('public.pem');
final privateKey = RSAKeyParser().parse(privatePem) as RSAPrivateKey;

// Generate and export
final pair = generateRSAKeyPair(bitLength: 3072);
final pem = RSAKeyEncoder.encodePublicKey(pair.publicKey);
```

### Encryption

```dart
final encrypter = Encrypter(
  RSA(
    publicKey: publicKey,
    privateKey: privateKey,
    encoding: RSAEncoding.OAEP,
    digest: RSADigest.SHA256,
  ),
);
final encrypted = encrypter.encrypt('Lorem ipsum');
```

### Signatures

```dart
// RSA-PSS (PS256), recommended
final signer = Signer(
  RSAPSSSigner(RSASignDigest.SHA256, publicKey: publicKey, privateKey: privateKey),
);

// PKCS#1 v1.5 (RS256 / RS512)
final legacy = Signer(
  RSASigner(RSASignDigest.SHA256, publicKey: publicKey, privateKey: privateKey),
);

final signature = signer.sign('hello world');
signer.verify('hello world', signature); // true
```

## Secure random

```dart
final bytes = SecureRandom(32).bytes;
```

Or from the command line:

```bash
dart pub global activate encrypt_plus
secure-random --length 32 --base 64
```

## Name clashes with PointyCastle

`SecureRandom`, `Signer`, `RSASigner`, `Algorithm` and `ChaCha20Poly1305`
exist in both packages. If you import `package:pointycastle/export.dart` too,
hide the ones you do not use:

```dart
import 'package:pointycastle/export.dart' hide RSASigner, Signer;
```

## Platform support

| | VM / Flutter native | Web (JavaScript) | Web (WebAssembly) |
| --- | --- | --- | --- |
| Everything else | ✅ | ✅ | ✅ |
| ChaCha20-Poly1305 | ✅ | ❌ | ✅ |
| `encrypt_io.dart` | ✅ | ❌ | ❌ |

## Security

See [AUDIT.md](AUDIT.md) for the issues found and fixed when taking over the
package. Report vulnerabilities privately through
[GitHub security advisories](https://github.com/raphrmx/encrypt_plus/security/advisories/new).

## Credits

Originally written by [Leo Cavalcante](https://github.com/leocavalcante) and
the `encrypt` contributors, under the BSD 3-Clause license. Maintained since
2026 by [Raphaël Vrient](https://github.com/raphrmx).
