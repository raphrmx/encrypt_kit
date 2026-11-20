import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:encrypt_kit/encrypt.dart';
import 'package:pointycastle/api.dart' show InvalidCipherTextException;
import 'package:pointycastle/asymmetric/api.dart';
import 'package:test/test.dart';

import 'fixtures/keys.dart';

/// Regression tests for the defects found while auditing `encrypt` 5.0.4.
void main() {
  final key = Key(Uint8List.fromList(List.generate(32, (i) => i)));
  final iv = IV(Uint8List.fromList(List.generate(12, (i) => i)));

  group('AES-GCM without padding', () {
    final encrypter = Encrypter(AES(key, mode: AESMode.gcm, padding: null));

    test('appends the authentication tag', () {
      final encrypted = encrypter.encrypt('0123456789abcdef', iv: iv);
      expect(encrypted.bytes.length, 16 + 16);
    });

    test('gives the same result as with the default padding', () {
      final padded = Encrypter(AES(key, mode: AESMode.gcm));
      expect(
        encrypter.encrypt('0123456789abcdef', iv: iv),
        padded.encrypt('0123456789abcdef', iv: iv),
      );
    });

    test('detects tampering', () {
      final encrypted = encrypter.encrypt('0123456789abcdef', iv: iv);
      final tampered = Uint8List.fromList(encrypted.bytes)..[0] ^= 1;
      expect(
        () => encrypter.decrypt(Encrypted(tampered), iv: iv),
        throwsA(isA<InvalidCipherTextException>()),
      );
    });
  });

  group('AES without padding', () {
    test('rejects a partial block with an ArgumentError', () {
      final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: null));
      expect(
        () => encrypter.encrypt('not a multiple of 16', iv: IV(Uint8List(16))),
        throwsArgumentError,
      );
    });
  });

  group('Fernet', () {
    final fernet = Fernet(key, clock: Clock.fixed(DateTime.utc(2026)));
    final token = fernet.encrypt(Uint8List.fromList([1, 2, 3]));

    test('rejects truncated and malformed tokens with a StateError', () {
      for (final bytes in [
        <int>[],
        [0x80],
        [0x80, 1, 2],
        token.bytes.sublist(0, token.bytes.length - 1),
        token.bytes.sublist(0, 57),
      ]) {
        expect(
          () => fernet.decrypt(Encrypted(Uint8List.fromList(bytes))),
          throwsStateError,
          reason: 'length ${bytes.length}',
        );
      }
    });

    test('rejects a token with a modified HMAC', () {
      final tampered = Uint8List.fromList(token.bytes)
        ..[token.bytes.length - 1] ^= 1;
      expect(() => fernet.decrypt(Encrypted(tampered)), throwsStateError);
    });

    test('rejects an expired token', () {
      final later = Fernet(
        key,
        clock: Clock.fixed(DateTime.utc(2026).add(const Duration(hours: 1))),
      );
      expect(() => later.decrypt(token, ttl: 60), throwsStateError);
      expect(later.decrypt(token, ttl: 7200), [1, 2, 3]);
    });
  });

  group('RSASigner', () {
    final parser = RSAKeyParser();
    final publicKey = parser.parse(publicPem) as RSAPublicKey;
    final privateKey = parser.parse(privatePem) as RSAPrivateKey;

    test('supports SHA-512 (crashed in 5.x)', () {
      final signer = Signer(
        RSASigner(
          RSASignDigest.SHA512,
          publicKey: publicKey,
          privateKey: privateKey,
        ),
      );
      expect(signer.verify('msg', signer.sign('msg')), isTrue);
    });

    test('returns false, never throws, on garbage signatures', () {
      final signer = Signer(
        RSASigner(RSASignDigest.SHA256, publicKey: publicKey),
      );
      for (final length in [0, 1, 64, 127, 128, 129, 256]) {
        final garbage = Encrypted(Uint8List(length)..fillRange(0, length, 7));
        expect(signer.verify('msg', garbage), isFalse, reason: '$length');
      }
    });
  });

  group('decodeHexString', () {
    test('rejects odd lengths (silently truncated in 5.x)', () {
      expect(() => decodeHexString('abc'), throwsFormatException);
    });

    test('rejects invalid characters', () {
      expect(() => decodeHexString('zz'), throwsFormatException);
    });

    test('accepts upper case', () {
      expect(decodeHexString('CAFE'), [0xca, 0xfe]);
    });
  });

  group('RSAKeyParser', () {
    test('ignores surrounding whitespace and blank lines', () {
      expect(RSAKeyParser().parse('\n  $publicPem  \n\n'), isA<RSAPublicKey>());
    });

    test('reports malformed keys as FormatException', () {
      expect(
        () => RSAKeyParser().parse(
          '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----',
        ),
        throwsFormatException,
      );
      expect(() => RSAKeyParser().parse(''), throwsFormatException);
    });
  });
}
