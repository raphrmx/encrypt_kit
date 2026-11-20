import 'dart:typed_data';

import 'package:encrypt_kit/encrypt.dart';
import 'package:pointycastle/api.dart' show InvalidCipherTextException;
import 'package:pointycastle/asymmetric/api.dart';
import 'package:test/test.dart';

import 'fixtures/keys.dart';

void main() {
  group('ChaCha20Poly1305 on dart2js', testOn: 'dart2js', () {
    test('is reported as unsupported', () {
      expect(ChaCha20Poly1305.isSupported, isFalse);
      expect(
        () => ChaCha20Poly1305(Key.fromSecureRandom(32)),
        throwsUnsupportedError,
      );
    });
  });

  group('ChaCha20Poly1305', testOn: '!dart2js', () {
    final key = Key.fromSecureRandom(32);
    late final encrypter = Encrypter(ChaCha20Poly1305(key));

    test('round trips and appends a 16 byte tag', () {
      final nonce = IV.fromSecureRandom(12);
      final encrypted = encrypter.encrypt('hello', iv: nonce);
      expect(encrypted.bytes.length, 5 + ChaCha20Poly1305.tagLength);
      expect(encrypter.decrypt(encrypted, iv: nonce), 'hello');
    });

    test('detects a wrong nonce or associated data', () {
      final nonce = IV.fromSecureRandom(12);
      final aad = Uint8List.fromList([1, 2, 3]);
      final encrypted =
          encrypter.encrypt('hello', iv: nonce, associatedData: aad);

      expect(
        () => encrypter.decrypt(encrypted, iv: IV.fromSecureRandom(12)),
        throwsA(isA<InvalidCipherTextException>()),
      );
      expect(
        () => encrypter.decrypt(encrypted, iv: nonce),
        throwsA(isA<InvalidCipherTextException>()),
      );
    });

    test('validates key and nonce', () {
      expect(() => ChaCha20Poly1305(Key.fromLength(16)), throwsArgumentError);
      expect(() => encrypter.encrypt('x'), throwsStateError);
      expect(
        () => encrypter.encrypt('x', iv: IV.fromLength(8)),
        throwsArgumentError,
      );
    });
  });

  group('Key.fromPassword', () {
    final salt = Uint8List.fromList(List.generate(16, (i) => i));

    test('is deterministic for a given salt', () {
      final a = Key.fromPassword('secret', salt: salt, iterations: 10);
      final b = Key.fromPassword('secret', salt: salt, iterations: 10);
      expect(a, b);
      expect(a.length, 32);
    });

    test('depends on the salt and the length', () {
      final a = Key.fromPassword('secret', salt: salt, iterations: 10);
      final b = Key.fromPassword(
        'secret',
        salt: Uint8List.fromList(List.generate(16, (i) => i + 1)),
        iterations: 10,
      );
      expect(a, isNot(b));
      expect(
        Key.fromPassword('secret', salt: salt, iterations: 10, length: 16)
            .length,
        16,
      );
    });

    test('rejects short salts and invalid parameters', () {
      expect(
        () => Key.fromPassword('secret', salt: Uint8List(8)),
        throwsArgumentError,
      );
      expect(
        () => Key.fromPassword('secret', salt: salt, iterations: 0),
        throwsRangeError,
      );
    });
  });

  group('Encrypted.base64Url', () {
    test('uses the URL-safe alphabet and round trips', () {
      final encrypted = Encrypted(Uint8List.fromList([0xfb, 0xff, 0xbf]));
      expect(encrypted.base64, '+/+/');
      expect(encrypted.base64Url, '-_-_');
      expect(Encrypted.fromBase64(encrypted.base64Url), encrypted);
    });
  });

  group('RSAKeyEncoder', () {
    final parser = RSAKeyParser();
    final publicKey = parser.parse(public2048Pem) as RSAPublicKey;
    final privateKey = parser.parse(private2048Pem) as RSAPrivateKey;

    test('re-encodes the fixtures byte for byte', () {
      expect(RSAKeyEncoder.encodePublicKey(publicKey), public2048Pem.trim());
      expect(
        RSAKeyEncoder.encodePrivateKey(
          privateKey,
          format: RSAKeyFormat.pkcs1,
        ),
        private2048Pem.trim(),
      );
    });

    for (final format in RSAKeyFormat.values) {
      test('round trips through RSAKeyParser in ${format.name}', () {
        final pub = parser.parse(
          RSAKeyEncoder.encodePublicKey(publicKey, format: format),
        ) as RSAPublicKey;
        final priv = parser.parse(
          RSAKeyEncoder.encodePrivateKey(privateKey, format: format),
        ) as RSAPrivateKey;

        expect(pub.modulus, publicKey.modulus);
        expect(pub.exponent, publicKey.exponent);
        expect(priv.modulus, privateKey.modulus);
        expect(priv.privateExponent, privateKey.privateExponent);
        expect(priv.p, privateKey.p);
        expect(priv.q, privateKey.q);
      });
    }
  });

  group('RSAPSSSigner', () {
    final parser = RSAKeyParser();
    final publicKey = parser.parse(public2048Pem) as RSAPublicKey;
    final privateKey = parser.parse(private2048Pem) as RSAPrivateKey;

    for (final digest in RSASignDigest.values) {
      test('signs and verifies with ${digest.name}', () {
        final signer = Signer(
          RSAPSSSigner(digest, publicKey: publicKey, privateKey: privateKey),
        );
        final a = signer.sign('hello');
        final b = signer.sign('hello');

        expect(a, isNot(b), reason: 'PSS signatures are randomized');
        expect(signer.verify('hello', a), isTrue);
        expect(signer.verify('hello', b), isTrue);
        expect(signer.verify('hellO', a), isFalse);
        expect(signer.verify('hello', Encrypted(Uint8List(3))), isFalse);
      });
    }

    test('requires the right key', () {
      expect(
        () => Signer(RSAPSSSigner(RSASignDigest.SHA256)).sign('x'),
        throwsStateError,
      );
      expect(
        () => Signer(RSAPSSSigner(RSASignDigest.SHA256))
            .verify('x', Encrypted(Uint8List(1))),
        throwsStateError,
      );
    });
  });

  group('generateRSAKeyPair', () {
    test(
      'generates a usable 2048-bit key pair',
      () {
        final pair = generateRSAKeyPair();
        expect(pair.publicKey.modulus!.bitLength, 2048);
        expect(pair.publicKey.publicExponent, BigInt.from(65537));

        final rsa = Encrypter(
          RSA(
            publicKey: pair.publicKey,
            privateKey: pair.privateKey,
            encoding: RSAEncoding.OAEP,
            digest: RSADigest.SHA256,
          ),
        );
        expect(rsa.decrypt(rsa.encrypt('hello')), 'hello');
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test('rejects keys shorter than 2048 bits', () {
      expect(() => generateRSAKeyPair(bitLength: 1024), throwsArgumentError);
    });
  });
}
