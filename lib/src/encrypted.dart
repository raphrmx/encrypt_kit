// The wrapped bytes are final and value equality is part of the 5.x API.
// ignore_for_file: avoid_equals_and_hash_code_on_mutable_classes

import 'dart:convert' as convert;
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:encrypt_plus/src/secure_random.dart';
import 'package:encrypt_plus/src/utils.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';

/// A sequence of bytes: a cipher text, a key, an IV or a signature.
///
/// [Key] and [IV] extend it, so all the factories below are also available
/// on them.
class Encrypted {
  /// Wraps [_bytes] without copying them.
  Encrypted(this._bytes);

  /// Decodes a hexadecimal string.
  ///
  /// Throws a [FormatException] when [encoded] is not valid hexadecimal.
  Encrypted.fromBase16(String encoded) : _bytes = decodeHexString(encoded);

  /// Decodes a base 64 string (standard or URL-safe alphabet).
  Encrypted.fromBase64(String encoded)
      : _bytes = convert.base64.decode(encoded);

  /// Alias of [Encrypted.fromBase64].
  Encrypted.from64(String encoded) : _bytes = convert.base64.decode(encoded);

  /// Encodes [input] as UTF-8.
  Encrypted.fromUtf8(String input)
      : _bytes = Uint8List.fromList(convert.utf8.encode(input));

  /// Generates [length] cryptographically secure random bytes.
  Encrypted.fromLength(int length) : _bytes = SecureRandom(length).bytes;

  /// Generates [length] cryptographically secure random bytes.
  Encrypted.fromSecureRandom(int length) : _bytes = SecureRandom(length).bytes;

  /// Creates [length] zero bytes.
  ///
  /// NOT CRYPTOGRAPHICALLY SECURE: only use it for tests or for protocols
  /// that explicitly require a zero IV.
  Encrypted.allZerosOfLength(int length) : _bytes = Uint8List(length);

  final Uint8List _bytes;

  /// The raw bytes.
  Uint8List get bytes => _bytes;

  /// The bytes as a lower case hexadecimal string.
  String get base16 => encodeHexString(_bytes);

  /// The bytes as a standard base 64 string.
  String get base64 => convert.base64.encode(_bytes);

  /// The bytes as a URL-safe base 64 string (RFC 4648 §5), as used by the
  /// Fernet specification and JSON Web Tokens.
  String get base64Url => convert.base64Url.encode(_bytes);

  /// Compares the bytes of two values.
  ///
  /// This comparison is not constant time: do not use it to check secrets
  /// such as MACs.
  @override
  bool operator ==(Object other) {
    if (identical(this, other)) {
      return true;
    }
    if (other is Encrypted) {
      return const ListEquality<int>().equals(bytes, other.bytes);
    }
    return false;
  }

  @override
  int get hashCode => const ListEquality<int>().hash(bytes);
}

/// An initialization vector (or nonce).
///
/// Never reuse an IV with the same key: generate a new one with
/// [IV.fromSecureRandom] for every message and store it next to the cipher
/// text.
class IV extends Encrypted {
  /// Wraps [bytes] without copying them.
  IV(super.bytes);

  /// Decodes a hexadecimal string.
  IV.fromBase16(super.encoded) : super.fromBase16();

  /// Decodes a base 64 string.
  IV.fromBase64(super.encoded) : super.fromBase64();

  /// Encodes [input] as UTF-8.
  IV.fromUtf8(super.input) : super.fromUtf8();

  /// Generates [length] cryptographically secure random bytes.
  IV.fromLength(super.length) : super.fromLength();

  /// Generates [length] cryptographically secure random bytes.
  IV.fromSecureRandom(int length) : super(SecureRandom(length).bytes);

  /// Creates [length] zero bytes. NOT CRYPTOGRAPHICALLY SECURE.
  IV.allZerosOfLength(super.length) : super.allZerosOfLength();
}

/// A symmetric encryption key.
class Key extends Encrypted {
  /// Wraps [bytes] without copying them.
  Key(super.bytes);

  /// Decodes a hexadecimal string.
  Key.fromBase16(super.encoded) : super.fromBase16();

  /// Decodes a base 64 string.
  Key.fromBase64(super.encoded) : super.fromBase64();

  /// Encodes [input] as UTF-8.
  ///
  /// The string is used as is, which is only secure when it already is a
  /// random secret of the right length. To turn a human password into a key,
  /// use [Key.fromPassword].
  Key.fromUtf8(super.input) : super.fromUtf8();

  /// Generates [length] cryptographically secure random bytes.
  Key.fromLength(super.length) : super.fromLength();

  /// Generates [length] cryptographically secure random bytes.
  Key.fromSecureRandom(int length) : super(SecureRandom(length).bytes);

  /// Creates [length] zero bytes. NOT CRYPTOGRAPHICALLY SECURE.
  Key.allZerosOfLength(super.length) : super.allZerosOfLength();

  /// Derives a key from a human [password] with PBKDF2-HMAC-SHA256.
  ///
  /// - [salt]: random and unique per password, at least 16 bytes (generate
  ///   it with `SecureRandom(16).bytes` and store it with the cipher text).
  /// - [iterations]: work factor, 600 000 by default as recommended by OWASP
  ///   (2023). Deriving takes about 2 s on a desktop VM and more on the web,
  ///   so run it outside of the UI isolate (`Isolate.run`) when possible.
  /// - [length]: key length in bytes, 32 by default (AES-256).
  ///
  /// Throws an [ArgumentError] when [salt] is shorter than 16 bytes or
  /// [iterations] / [length] are not positive.
  ///
  /// ```dart
  /// final salt = SecureRandom(16).bytes;
  /// final key = Key.fromPassword('correct horse battery staple', salt: salt);
  /// ```
  factory Key.fromPassword(
    String password, {
    required Uint8List salt,
    int iterations = 600000,
    int length = 32,
  }) {
    if (salt.length < 16) {
      throw ArgumentError.value(
        salt.length,
        'salt',
        'The salt must be at least 16 bytes long',
      );
    }
    RangeError.checkValueInInterval(iterations, 1, 0x7fffffff, 'iterations');
    RangeError.checkValueInInterval(length, 1, 0x7fffffff, 'length');

    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(salt, iterations, length));
    return Key(
      derivator.process(Uint8List.fromList(convert.utf8.encode(password))),
    );
  }

  /// Stretches this key to [desiredKeyLength] bytes with PBKDF2-HMAC-SHA1.
  ///
  /// Kept for compatibility with `encrypt` 5.x, which it reproduces bit for
  /// bit. Prefer [Key.fromPassword] for new code: SHA-1 and the default 100
  /// iterations are far below current recommendations, and when [salt] is
  /// omitted a random salt is generated and lost, so the same input never
  /// gives the same key twice.
  Key stretch(
    int desiredKeyLength, {
    int iterationCount = 100,
    Uint8List? salt,
  }) {
    final params = Pbkdf2Parameters(
      salt ?? SecureRandom(desiredKeyLength).bytes,
      iterationCount,
      desiredKeyLength,
    );
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA1Digest(), 64))..init(params);

    return Key(pbkdf2.process(_bytes));
  }

  /// The key length in bytes.
  int get length => bytes.lengthInBytes;
}
