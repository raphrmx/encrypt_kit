import 'dart:convert' as convert;
import 'dart:typed_data';

import 'package:encrypt_plus/src/algorithm.dart';
import 'package:encrypt_plus/src/encrypted.dart';

/// Front-end over a [SignerAlgorithm] working with strings and byte lists.
///
/// ```dart
/// final signer = Signer(RSASigner(RSASignDigest.SHA256, privateKey: key));
/// final signature = signer.sign('hello world');
/// ```
class Signer {
  /// Wraps [algo].
  Signer(this.algo);

  /// The wrapped signing algorithm.
  final SignerAlgorithm algo;

  /// Signs the UTF-8 encoding of [input].
  Encrypted sign(String input) => signBytes(convert.utf8.encode(input));

  /// Signs raw [bytes].
  Encrypted signBytes(List<int> bytes) => algo.sign(_toUint8List(bytes));

  /// Returns whether [signature] is a valid signature of [bytes].
  bool verifyBytes(List<int> bytes, Encrypted signature) =>
      algo.verify(_toUint8List(bytes), signature);

  /// Returns whether [signature] is a valid signature of [input].
  bool verify(String input, Encrypted signature) =>
      verifyBytes(convert.utf8.encode(input), signature);

  /// Same as [verify] with a hexadecimal [signature].
  bool verify16(String input, String signature) =>
      verify(input, Encrypted.fromBase16(signature));

  /// Same as [verify] with a base 64 [signature].
  bool verify64(String input, String signature) =>
      verify(input, Encrypted.fromBase64(signature));

  static Uint8List _toUint8List(List<int> bytes) =>
      bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
}
