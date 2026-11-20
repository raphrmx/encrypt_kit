import 'dart:typed_data';

import 'package:encrypt_kit/src/algorithm.dart';
import 'package:encrypt_kit/src/encrypted.dart';
import 'package:encrypt_kit/src/internal/fortuna.dart';
import 'package:encrypt_kit/src/rsa/rsa.dart';
import 'package:pointycastle/export.dart'
    hide Algorithm, RSASigner, SecureRandom, Signer;

/// RSA signatures with PSS padding (RFC 8017, `PS256` / `PS512` in JWT
/// terms), using MGF1 with the same digest and a salt as long as the digest.
///
/// PSS is randomized: signing the same message twice gives two different,
/// equally valid signatures.
///
/// ```dart
/// final signer = Signer(
///   RSAPSSSigner(RSASignDigest.SHA256, privateKey: privateKey),
/// );
/// final signature = signer.sign('hello world');
/// ```
class RSAPSSSigner implements SignerAlgorithm {
  /// Creates a PSS signer hashing messages with [digest].
  ///
  /// [privateKey] is needed to sign, [publicKey] to verify.
  RSAPSSSigner(this.digest, {this.publicKey, this.privateKey});

  /// The message digest, also used by MGF1.
  final RSASignDigest digest;

  /// Key used to verify, `null` when not needed.
  final RSAPublicKey? publicKey;

  /// Key used to sign, `null` when not needed.
  final RSAPrivateKey? privateKey;

  /// Signs [bytes] with the private key.
  ///
  /// Throws a [StateError] when no private key was given.
  @override
  Encrypted sign(Uint8List bytes) {
    final key = privateKey;
    if (key == null) {
      throw StateError("Can't sign without a private key, null given.");
    }

    final signer = _createSigner()
      ..init(true, _params(PrivateKeyParameter<RSAPrivateKey>(key)));
    return Encrypted(signer.generateSignature(bytes).bytes);
  }

  /// Returns whether [signature] is a valid PSS signature of [bytes].
  ///
  /// Returns `false`, never throws, for a malformed signature. Throws a
  /// [StateError] when no public key was given.
  @override
  bool verify(Uint8List bytes, Encrypted signature) {
    final key = publicKey;
    if (key == null) {
      throw StateError("Can't verify without a public key, null given.");
    }

    final signer = _createSigner()
      ..init(false, _params(PublicKeyParameter<RSAPublicKey>(key)));
    try {
      return signer.verifySignature(bytes, PSSSignature(signature.bytes));
      // Malformed signatures fail in many ways in the RSA engine: all of
      // them simply mean "invalid".
      // ignore: avoid_catches_without_on_clauses
    } catch (_) {
      return false;
    }
  }

  PSSSigner _createSigner() =>
      PSSSigner(RSAEngine(), _createDigest(), _createDigest());

  ParametersWithSaltConfiguration<CipherParameters> _params(
    CipherParameters keyParams,
  ) =>
      ParametersWithSaltConfiguration<CipherParameters>(
        keyParams,
        createSeededRandom(),
        _createDigest().digestSize,
      );

  Digest _createDigest() {
    switch (digest) {
      case RSASignDigest.SHA256:
        return SHA256Digest();
      case RSASignDigest.SHA512:
        return SHA512Digest();
    }
  }
}
