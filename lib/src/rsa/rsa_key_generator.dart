import 'package:encrypt_kit/src/internal/fortuna.dart';
import 'package:pointycastle/api.dart'
    show AsymmetricKeyPair, ParametersWithRandom;
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';

/// Generates a new RSA key pair.
///
/// - [bitLength]: modulus size, at least 2048 (default). Use 3072 or more for
///   keys that must stay secure beyond 2030.
/// - [publicExponent]: 65537 by default.
///
/// Generation is CPU intensive (around a second for 2048 bits on a desktop
/// VM, more on the web): run it outside of the UI isolate when possible.
///
/// Throws an [ArgumentError] when [bitLength] is below 2048.
///
/// ```dart
/// final pair = generateRSAKeyPair();
/// final rsa = RSA(publicKey: pair.publicKey, privateKey: pair.privateKey);
/// ```
AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRSAKeyPair({
  int bitLength = 2048,
  int publicExponent = 65537,
}) {
  if (bitLength < 2048) {
    throw ArgumentError.value(
      bitLength,
      'bitLength',
      'RSA keys shorter than 2048 bits are insecure',
    );
  }

  final generator = RSAKeyGenerator()
    ..init(
      ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.from(publicExponent), bitLength, 64),
        createSeededRandom(),
      ),
    );
  return generator.generateKeyPair();
}
