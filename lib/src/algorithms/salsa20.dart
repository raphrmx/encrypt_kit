import 'dart:typed_data';

import 'package:encrypt_kit/src/algorithm.dart';
import 'package:encrypt_kit/src/encrypted.dart';
import 'package:pointycastle/api.dart' show KeyParameter, ParametersWithIV;
import 'package:pointycastle/stream/salsa20.dart';

/// Salsa20 stream cipher (16 or 32 byte key, 8 byte IV).
///
/// Not authenticated: prefer `ChaCha20Poly1305` for new code.
class Salsa20 implements Algorithm {
  /// Creates a Salsa20 cipher with [key].
  Salsa20(this.key);

  /// The encryption key.
  final Key key;

  final Salsa20Engine _cipher = Salsa20Engine();

  /// Encrypts [bytes]. Throws a [StateError] when [iv] is missing.
  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    _cipher
      ..reset()
      ..init(true, _buildParams(iv));
    return Encrypted(_cipher.process(bytes));
  }

  /// Decrypts [encrypted]. Throws a [StateError] when [iv] is missing.
  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData}) {
    _cipher
      ..reset()
      ..init(false, _buildParams(iv));
    return _cipher.process(encrypted.bytes);
  }

  ParametersWithIV<KeyParameter> _buildParams(IV? iv) {
    if (iv == null) {
      throw StateError('IV is required.');
    }
    return ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes);
  }
}
