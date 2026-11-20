import 'dart:convert' as convert;
import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt_plus/src/utils.dart';

/// A sequence of cryptographically secure random bytes.
///
/// Bytes come from [Random.secure], backed by the operating system CSPRNG
/// (or `crypto.getRandomValues` on the web).
///
/// Note: `package:pointycastle` also declares a `SecureRandom` type. When
/// both libraries are imported, hide one of them.
///
/// ```dart
/// final salt = SecureRandom(16).bytes;
/// ```
class SecureRandom {
  /// Generates [length] secure random bytes.
  ///
  /// Throws an [RangeError] when [length] is negative.
  SecureRandom(int length) : _bytes = _generate(length);

  static final Random _generator = Random.secure();

  final Uint8List _bytes;

  static Uint8List _generate(int length) {
    RangeError.checkNotNegative(length, 'length');
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _generator.nextInt(256);
    }
    return bytes;
  }

  /// The random bytes.
  Uint8List get bytes => _bytes;

  /// The random bytes as a lower case hexadecimal string.
  String get base16 => encodeHexString(_bytes);

  /// The random bytes as a standard base 64 string.
  String get base64 => convert.base64.encode(_bytes);

  /// The random bytes decoded as UTF-8.
  ///
  /// Random bytes are rarely valid UTF-8: this getter throws a
  /// [FormatException] in most cases and is only kept for compatibility.
  String get utf8 => convert.utf8.decode(_bytes);

  /// The number of random bytes.
  int get length => _bytes.length;
}
