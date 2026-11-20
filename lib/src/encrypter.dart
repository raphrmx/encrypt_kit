import 'dart:convert' as convert;
import 'dart:typed_data';

import 'package:encrypt_plus/src/algorithm.dart';
import 'package:encrypt_plus/src/encrypted.dart';

/// Front-end over an [Algorithm] working with strings and byte lists.
///
/// ```dart
/// final encrypter = Encrypter(AES(key, mode: AESMode.gcm));
/// final encrypted = encrypter.encrypt('secret', iv: iv);
/// final decrypted = encrypter.decrypt(encrypted, iv: iv);
/// ```
class Encrypter {
  /// Wraps [algo].
  Encrypter(this.algo);

  /// The wrapped algorithm.
  final Algorithm algo;

  /// Encrypts raw [input] bytes.
  Encrypted encryptBytes(
    List<int> input, {
    IV? iv,
    Uint8List? associatedData,
  }) {
    final bytes = input is Uint8List ? input : Uint8List.fromList(input);
    return algo.encrypt(bytes, iv: iv, associatedData: associatedData);
  }

  /// Encrypts the UTF-8 encoding of [input].
  Encrypted encrypt(
    String input, {
    IV? iv,
    Uint8List? associatedData,
  }) {
    return encryptBytes(
      convert.utf8.encode(input),
      iv: iv,
      associatedData: associatedData,
    );
  }

  /// Decrypts [encrypted] and returns the raw bytes.
  List<int> decryptBytes(
    Encrypted encrypted, {
    IV? iv,
    Uint8List? associatedData,
  }) {
    return algo
        .decrypt(encrypted, iv: iv, associatedData: associatedData)
        .toList();
  }

  /// Decrypts [encrypted] and decodes the result as UTF-8.
  ///
  /// Malformed UTF-8 sequences are replaced by U+FFFD instead of throwing,
  /// as in `encrypt` 5.x. With a non authenticated mode, a wrong key or IV
  /// therefore returns garbage instead of failing: use an authenticated
  /// algorithm (AES-GCM, ChaCha20-Poly1305, Fernet) to detect it.
  String decrypt(
    Encrypted encrypted, {
    IV? iv,
    Uint8List? associatedData,
  }) {
    return convert.utf8.decode(
      decryptBytes(encrypted, iv: iv, associatedData: associatedData),
      allowMalformed: true,
    );
  }

  /// Shortcut for `decrypt(Encrypted.fromBase16(encoded))`.
  String decrypt16(String encoded, {IV? iv, Uint8List? associatedData}) {
    return decrypt(
      Encrypted.fromBase16(encoded),
      iv: iv,
      associatedData: associatedData,
    );
  }

  /// Shortcut for `decrypt(Encrypted.fromBase64(encoded))`.
  String decrypt64(String encoded, {IV? iv, Uint8List? associatedData}) {
    return decrypt(
      Encrypted.fromBase64(encoded),
      iv: iv,
      associatedData: associatedData,
    );
  }
}
