// Test vectors are long base 64 strings.
// ignore_for_file: lines_longer_than_80_chars

import 'dart:convert';
import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:encrypt_kit/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:test/test.dart';

import 'fixtures/keys.dart';

/// Vectors generated with the Python `cryptography` package (v50), the
/// reference implementation used by most back ends.
void main() {
  final key = Key(Uint8List.fromList(List.generate(32, (i) => i)));
  final nonce = IV(Uint8List.fromList(List.generate(12, (i) => 100 + i)));
  final aad = Uint8List.fromList(utf8.encode('header'));
  const plainText = 'Lorem ipsum dolor sit amet';

  group('Python cryptography interop', () {
    test('AES-256-GCM', () {
      final encrypter = Encrypter(AES(key, mode: AESMode.gcm));
      const expected =
          'BHSsAxTJP+5NFzLIvgoGkjDidWP/TJIfwqVe7BrA7ptTu4tVvNsVeVhF';

      expect(
        encrypter.encrypt(plainText, iv: nonce, associatedData: aad).base64,
        expected,
      );
      expect(
        encrypter.decrypt64(expected, iv: nonce, associatedData: aad),
        plainText,
      );
    });

    test('ChaCha20-Poly1305', testOn: '!dart2js', () {
      final encrypter = Encrypter(ChaCha20Poly1305(key));
      const expected =
          'eH7Jr/WFHyKIq3hflua0/ALm4V3rcIrAo0tkPSpPxXtzKaRwQnEK3eQF';

      expect(
        encrypter.encrypt(plainText, iv: nonce, associatedData: aad).base64,
        expected,
      );
      expect(
        encrypter.decrypt64(expected, iv: nonce, associatedData: aad),
        plainText,
      );
    });

    test('ChaCha20-Poly1305 over several 64 byte blocks', testOn: '!dart2js',
        () {
      final input = Uint8List.fromList(List.generate(1000, (i) => i % 256));
      final algorithm = ChaCha20Poly1305(key);
      final encrypted = algorithm.encrypt(input, iv: nonce);

      expect(encrypted.bytes.length, 1016);
      expect(
        encrypted.base64.substring(encrypted.base64.length - 60),
        'QmWRCw3Ss2mYK3axZK/RkFT19SxoLJ9dAJcAuQ/GPrI50B7zQt+JEZT57qM=',
      );
      expect(algorithm.decrypt(encrypted, iv: nonce), input);
    });

    test('PBKDF2-HMAC-SHA256', () {
      final derived = Key.fromPassword(
        'password',
        salt: Uint8List.fromList(utf8.encode('0123456789abcdef')),
        iterations: 1000,
      );
      expect(
        derived.base16,
        '8514638175a45bc45eb1f22f04ff7d27f4f8be480498c455ff4b494ce8d1e7d2',
      );
    });

    test('Fernet token from Python', () {
      const token =
          'gAAAAABlU_EAh7Sk9-z708mqYSvbR71wpFtL-x8HpmEhswJcnehgX1o6Kf4UmJ03aWHl9jgiP995JJDchwtOry5u47ZYzWWSQw==';
      final fernet = Fernet(
        Key.fromBase64('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='),
        clock: Clock.fixed(DateTime.utc(2023, 11, 15)),
      );

      final encrypted = Encrypted.fromBase64(token);
      expect(utf8.decode(fernet.decrypt(encrypted)), 'hello fernet');
      expect(fernet.extractTimestamp(encrypted.bytes), 1700000000);
      expect(encrypted.base64Url, token);
    });

    group('RSA signatures (2048-bit key)', () {
      final parser = RSAKeyParser();
      final publicKey = parser.parse(public2048Pem) as RSAPublicKey;
      final privateKey = parser.parse(private2048Pem) as RSAPrivateKey;

      test('PKCS#1 v1.5 SHA-512 (RS512) is deterministic and matches', () {
        const expected =
            'Bm/32MN0qRWotqIPwHP/S2VnfZVPGL6Rmk7HHcrbZpBsjGI/iI++lU1EVQ3285PFkbTgokySgz83TTItrepXFAR92Y7x4BWY/xA+JT0M6Ar3Rz1yi11BTb3/GEncbhFZ/CWGvzkwWAt3OCPVCk9oIWc82y2HY83gYoKCoOydGvmpN5SBKnwTy2dQKpob73iE+JokePgXhlcTZKG4UwUd7Vwzoqfl2V/J8TGKzQuufeoL+r7fCl+SkTUaz/sm1Gh3ArPadGLKf1n3psyEwiicBU6gHkj9XICZ2hd1nWm+UuX47Tgwnsp1DzOtQAf5Q0bPe/1k3CFK0CSjc+O3XRtUgw==';
        final signer = Signer(
          RSASigner(
            RSASignDigest.SHA512,
            publicKey: publicKey,
            privateKey: privateKey,
          ),
        );

        expect(signer.sign('hello world').base64, expected);
        expect(signer.verify64('hello world', expected), isTrue);
        expect(signer.verify64('hello world!', expected), isFalse);
      });

      test('PSS SHA-256 (PS256) signature from Python verifies', () {
        const pythonSignature =
            'Epu/ZAocCavY28jDhdaYtVYvLa0OCerwZXJERPNpMlV4kLeSK9qVyW2N3Ftu7MNjBp87aboV+KGhGhHCMwXeNfppxPXV4ErN9RE8AZ9OF+oljcpu4sTfe4coieJVZBKwaGkY4IGssmxXu2lGoat9RV1kA2nOG2klNtZOe0pMiTfuuWmkHjgKbhVsBOVEiUgtndNCO/J/xEGrq6K5lF5269rrgWwZwLGCVhOqXXsR1Efe6mxo1wqSNwLnbhQkqcEQMpJiqgqsV6lBl0Zd9MIoU3KvJL4Mu2T5vXvivCVU4p/ecru+PvN1+XZM+ehFqVftmT+k/nDfJemlL3VMH6qG9A==';
        final signer = Signer(
          RSAPSSSigner(RSASignDigest.SHA256, publicKey: publicKey),
        );

        expect(signer.verify64('hello world', pythonSignature), isTrue);
        expect(signer.verify64('hello world!', pythonSignature), isFalse);
      });
    });
  });
}
