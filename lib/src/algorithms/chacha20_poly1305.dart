import 'dart:typed_data';

import 'package:encrypt_plus/src/algorithm.dart';
import 'package:encrypt_plus/src/encrypted.dart';
import 'package:pointycastle/api.dart'
    show AEADParameters, InvalidCipherTextException, KeyParameter;
import 'package:pointycastle/macs/poly1305.dart';
import 'package:pointycastle/stream/chacha20poly1305.dart' as pc;
import 'package:pointycastle/stream/chacha7539.dart';

/// ChaCha20-Poly1305 authenticated encryption (RFC 8439).
///
/// A fast, constant-time alternative to AES-GCM on devices without AES
/// hardware acceleration. Uses a 32 byte [Key] and a 12 byte nonce passed as
/// [IV]. The 16 byte authentication tag is appended to the cipher text.
///
/// Never reuse a nonce with the same key: generate one per message with
/// `IV.fromSecureRandom(12)`.
///
/// Not available on the web when compiled to JavaScript: see [isSupported].
///
/// Note: `package:pointycastle` also declares a `ChaCha20Poly1305` class.
/// When both libraries are imported, hide one of them.
///
/// ```dart
/// final encrypter = Encrypter(ChaCha20Poly1305(Key.fromSecureRandom(32)));
/// final nonce = IV.fromSecureRandom(12);
/// final encrypted = encrypter.encrypt('secret', iv: nonce);
/// ```
class ChaCha20Poly1305 implements Algorithm {
  /// Creates a ChaCha20-Poly1305 cipher.
  ///
  /// Throws an [ArgumentError] when [key] is not 32 bytes long and an
  /// [UnsupportedError] when compiled to JavaScript (see [isSupported]).
  ChaCha20Poly1305(this.key) {
    if (!isSupported) {
      throw UnsupportedError(
        'ChaCha20-Poly1305 needs 64-bit integers, which are not available '
        'when compiled to JavaScript. Use AES-GCM, or compile the web app to '
        'WebAssembly.',
      );
    }
    if (key.length != keyLength) {
      throw ArgumentError.value(
        key.length,
        'key',
        'ChaCha20-Poly1305 key must be $keyLength bytes long',
      );
    }
  }

  /// Whether ChaCha20-Poly1305 is available on the current platform.
  ///
  /// `true` on the Dart VM, Flutter native and WebAssembly; `false` on the
  /// web when compiled to JavaScript (dart2js), where PointyCastle's Poly1305
  /// implementation is unavailable.
  static bool get isSupported => !identical(1, 1.0);

  /// Required key length in bytes.
  static const int keyLength = 32;

  /// Required nonce length in bytes.
  static const int nonceLength = 12;

  /// Authentication tag length in bytes.
  static const int tagLength = 16;

  /// The encryption key.
  final Key key;

  /// Encrypts [bytes] and appends the authentication tag.
  ///
  /// Throws a [StateError] when [iv] is missing and an [ArgumentError] when
  /// it is not 12 bytes long.
  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    return Encrypted(_process(true, bytes, iv, associatedData));
  }

  /// Verifies the authentication tag and decrypts [encrypted].
  ///
  /// Throws an `InvalidCipherTextException` when the tag does not match
  /// (tampered data, wrong key, nonce or associated data).
  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData}) {
    return _process(false, encrypted.bytes, iv, associatedData);
  }

  Uint8List _process(
    bool forEncryption,
    Uint8List input,
    IV? iv,
    Uint8List? associatedData,
  ) {
    if (iv == null) {
      throw StateError('IV is required.');
    }
    if (iv.bytes.length != nonceLength) {
      throw ArgumentError.value(
        iv.bytes.length,
        'iv',
        'ChaCha20-Poly1305 nonce must be $nonceLength bytes long',
      );
    }

    final cipher = pc.ChaCha20Poly1305(ChaCha7539Engine(), Poly1305())
      ..init(
        forEncryption,
        AEADParameters(
          KeyParameter(key.bytes),
          tagLength * 8,
          iv.bytes,
          associatedData ?? Uint8List(0),
        ),
      );

    // PointyCastle's `process` shortcut does not call `doFinal`, which
    // drops the tag: drive the cipher explicitly.
    final output = Uint8List(cipher.getOutputSize(input.length));
    var length = cipher.processBytes(input, 0, input.length, output, 0);
    try {
      length += cipher.doFinal(output, length);
      // PointyCastle reports a bad tag as an ArgumentError: align it with
      // AES-GCM, which throws an InvalidCipherTextException.
      // ignore: avoid_catching_errors
    } on ArgumentError catch (error) {
      if (forEncryption) {
        rethrow;
      }
      throw InvalidCipherTextException(
        'ChaCha20-Poly1305 authentication failed: ${error.message}',
      );
    }
    return length == output.length
        ? output
        : Uint8List.sublistView(output, 0, length);
  }
}
