# encrypt_plus

[![pub package](https://img.shields.io/pub/v/encrypt_plus.svg)](https://pub.dev/packages/encrypt_plus)
[![CI](https://github.com/raphrmx/encrypt_plus/actions/workflows/ci.yml/badge.svg)](https://github.com/raphrmx/encrypt_plus/actions/workflows/ci.yml)

A set of high-level APIs over PointyCastle for two-way cryptography.

Maintained fork of [encrypt](https://pub.dev/packages/encrypt) by Leo
Cavalcante, updated to PointyCastle 4.

## Migrating from encrypt

Replace `encrypt` with `encrypt_plus` in `pubspec.yaml` and update the imports:

```dart
import 'package:encrypt_plus/encrypt.dart';
```

See the [CHANGELOG](CHANGELOG.md) for the changes.

## Algorithms

- AES (GCM, CBC, CTR, SIC, CFB-64, OFB-64, ECB)
- ChaCha20-Poly1305
- Salsa20
- Fernet
- RSA with PKCS1 and OAEP encoding
- RSA signatures (PKCS1 v1.5 and PSS)

## Usage

### AES

```dart
import 'package:encrypt_plus/encrypt.dart';

void main() {
  final key = Key.fromSecureRandom(32);
  final iv = IV.fromSecureRandom(12);
  final encrypter = Encrypter(AES(key, mode: AESMode.gcm));

  final encrypted = encrypter.encrypt('Lorem ipsum', iv: iv);
  final decrypted = encrypter.decrypt(encrypted, iv: iv);
}
```

### RSA

```dart
import 'package:encrypt_plus/encrypt.dart';
import 'package:encrypt_plus/encrypt_io.dart';
import 'package:pointycastle/asymmetric/api.dart';

Future<void> main() async {
  final publicKey = await parseKeyFromFile<RSAPublicKey>('public.pem');
  final privateKey = await parseKeyFromFile<RSAPrivateKey>('private.pem');

  final encrypter = Encrypter(
    RSA(publicKey: publicKey, privateKey: privateKey, encoding: RSAEncoding.OAEP),
  );
  final encrypted = encrypter.encrypt('Lorem ipsum');

  final signer = Signer(
    RSASigner(RSASignDigest.SHA256, publicKey: publicKey, privateKey: privateKey),
  );
  final signature = signer.sign('hello world');
}
```

More in the [example](example) folder.

### Secure random

```bash
dart pub global activate encrypt_plus
secure-random --length 32
```

## License

BSD 3-Clause. Originally written by
[Leo Cavalcante](https://github.com/leocavalcante) and the encrypt
contributors.
