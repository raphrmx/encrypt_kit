import 'dart:typed_data';

import 'package:encrypt_plus/src/encrypted.dart';

/// Interface implemented by every two-way encryption algorithm.
///
/// Use it through an `Encrypter` rather than directly, unless you need the
/// raw [Uint8List] API.
abstract class Algorithm {
  /// Encrypts [bytes].
  ///
  /// [iv] is the initialization vector (or nonce) and [associatedData] the
  /// additional authenticated data, for the algorithms that support them.
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData});

  /// Decrypts the [encrypted] value.
  ///
  /// [iv] and [associatedData] must be the values used to encrypt.
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData});
}

/// Interface implemented by every signing algorithm.
abstract class SignerAlgorithm {
  /// Signs [bytes] and returns the signature.
  Encrypted sign(Uint8List bytes);

  /// Returns whether [encrypted] is a valid signature of [bytes].
  bool verify(Uint8List bytes, Encrypted encrypted);
}
