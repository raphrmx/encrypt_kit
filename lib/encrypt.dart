/// High-level, two-way cryptography APIs built on top of PointyCastle.
///
/// This library is a drop-in replacement for `package:encrypt/encrypt.dart`:
/// replacing the import with `package:encrypt_plus/encrypt.dart` is enough to
/// migrate.
///
/// ```dart
/// import 'package:encrypt_plus/encrypt.dart';
///
/// final key = Key.fromSecureRandom(32);
/// final iv = IV.fromSecureRandom(12);
/// final encrypter = Encrypter(AES(key, mode: AESMode.gcm));
///
/// final encrypted = encrypter.encrypt('Hello', iv: iv);
/// final decrypted = encrypter.decrypt(encrypted, iv: iv);
/// ```
library;

export 'src/algorithm.dart';
export 'src/algorithms/aes.dart';
export 'src/algorithms/chacha20_poly1305.dart';
export 'src/algorithms/fernet.dart';
export 'src/algorithms/salsa20.dart';
export 'src/encrypted.dart';
export 'src/encrypter.dart';
export 'src/rsa/rsa.dart';
export 'src/rsa/rsa_key_encoder.dart';
export 'src/rsa/rsa_key_generator.dart';
export 'src/rsa/rsa_key_parser.dart';
export 'src/rsa/rsa_pss_signer.dart';
export 'src/secure_random.dart';
export 'src/signer.dart';
export 'src/utils.dart' show decodeHexString;
