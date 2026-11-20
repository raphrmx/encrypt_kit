// Examples print their results.
// ignore_for_file: avoid_print

import 'package:encrypt_plus/encrypt.dart';

void main() {
  final key = Key.fromSecureRandom(32);
  final nonce = IV.fromSecureRandom(12); // new for every message
  final encrypter = Encrypter(ChaCha20Poly1305(key));

  final encrypted = encrypter.encrypt('Lorem ipsum', iv: nonce);
  print(encrypter.decrypt(encrypted, iv: nonce)); // Lorem ipsum
}
