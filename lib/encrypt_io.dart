/// `dart:io` helpers to load PEM encoded RSA keys from the file system.
///
/// Not available on the web: import it only from VM or Flutter native code.
library;

import 'dart:io';

import 'package:encrypt_kit/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

/// Reads and parses the PEM encoded RSA key stored in [filename].
///
/// [T] is the expected key type ([RSAPublicKey] or [RSAPrivateKey]).
///
/// Throws a [FormatException] when the file is not a supported PEM key and a
/// [TypeError] when the key is not of type [T].
///
/// ```dart
/// final publicKey = await parseKeyFromFile<RSAPublicKey>('public.pem');
/// ```
Future<T> parseKeyFromFile<T extends RSAAsymmetricKey>(String filename) async {
  final key = await File(filename).readAsString();
  return RSAKeyParser().parse(key) as T;
}

/// Synchronous variant of [parseKeyFromFile].
T parseKeyFromFileSync<T extends RSAAsymmetricKey>(String filename) {
  final key = File(filename).readAsStringSync();
  return RSAKeyParser().parse(key) as T;
}
