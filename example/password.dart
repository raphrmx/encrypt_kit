// Examples print their results.
// ignore_for_file: avoid_print

import 'package:encrypt_plus/encrypt.dart';

void main() {
  // Store the salt and the nonce next to the cipher text: both are public.
  final salt = SecureRandom(16).bytes;
  final key = Key.fromPassword('correct horse battery staple', salt: salt);

  final nonce = IV.fromSecureRandom(12);
  final encrypter = Encrypter(AES(key, mode: AESMode.gcm));
  final encrypted = encrypter.encrypt('my secret note', iv: nonce);

  print(encrypter.decrypt(encrypted, iv: nonce)); // my secret note
}
