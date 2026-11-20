// Examples print their results.
// ignore_for_file: avoid_print

import 'package:encrypt_plus/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() {
  // Generate a key pair and export it to PEM.
  final pair = generateRSAKeyPair();
  final publicPem = RSAKeyEncoder.encodePublicKey(pair.publicKey);
  final privatePem = RSAKeyEncoder.encodePrivateKey(pair.privateKey);
  print(publicPem);

  // Load it back.
  final parser = RSAKeyParser();
  final publicKey = parser.parse(publicPem) as RSAPublicKey;
  final privateKey = parser.parse(privatePem) as RSAPrivateKey;

  // Sign with RSA-PSS (PS256).
  final signer = Signer(
    RSAPSSSigner(
      RSASignDigest.SHA256,
      publicKey: publicKey,
      privateKey: privateKey,
    ),
  );
  final signature = signer.sign('hello world');
  print(signer.verify('hello world', signature)); // true
}
