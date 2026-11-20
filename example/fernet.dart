// Examples print their results.
// ignore_for_file: avoid_print

import 'dart:convert';

import 'package:encrypt_plus/encrypt.dart';

void main() {
  const plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final key = Key.fromUtf8('my32lengthsupersecretnooneknows1');

  final b64key = Key.fromBase64(base64Url.encode(key.bytes));
  // For the ttl feature, call `fernet.decrypt(encrypted, ttl: 60)` directly.
  final fernet = Fernet(b64key);
  final encrypter = Encrypter(fernet);

  final encrypted = encrypter.encrypt(plainText);
  final decrypted = encrypter.decrypt(encrypted);

  print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  print(encrypted.base64Url); // random token, Python compatible
  print(fernet.extractTimestamp(encrypted.bytes)); // unix timestamp
}
