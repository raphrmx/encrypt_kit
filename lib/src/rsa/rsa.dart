// Enum values keep the upper case names of `encrypt` 5.x for compatibility.
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';

import 'package:encrypt_kit/src/algorithm.dart';
import 'package:encrypt_kit/src/encrypted.dart';
import 'package:encrypt_kit/src/utils.dart';
import 'package:pointycastle/export.dart'
    hide Algorithm, RSASigner, SecureRandom, Signer;

/// Shared state of the RSA encryption and signing algorithms.
abstract class AbstractRSA {
  /// Creates the underlying RSA cipher.
  ///
  /// [encoding] and [digest] only matter for encryption: signing always uses
  /// PKCS#1 v1.5 padding.
  AbstractRSA({
    this.publicKey,
    this.privateKey,
    RSAEncoding encoding = RSAEncoding.PKCS1,
    RSADigest digest = RSADigest.SHA1,
  }) : _cipher = encoding == RSAEncoding.OAEP
            ? _createOAEPCipher(digest)
            : PKCS1Encoding(RSAEngine());

  /// Key used to encrypt or verify, `null` when not needed.
  final RSAPublicKey? publicKey;

  /// Key used to decrypt or sign, `null` when not needed.
  final RSAPrivateKey? privateKey;

  final AsymmetricBlockCipher _cipher;

  static AsymmetricBlockCipher _createOAEPCipher(RSADigest digest) {
    switch (digest) {
      case RSADigest.SHA256:
        return OAEPEncoding.withSHA256(RSAEngine());
      case RSADigest.SHA512:
        return OAEPEncoding.withCustomDigest(SHA512Digest.new, RSAEngine());
      case RSADigest.SHA1:
        return OAEPEncoding.withSHA1(RSAEngine());
    }
  }

  PublicKeyParameter<RSAPublicKey> get _publicKeyParams {
    final key = publicKey;
    if (key == null) {
      throw StateError("Can't use a public key operation, null given.");
    }
    return PublicKeyParameter<RSAPublicKey>(key);
  }

  PrivateKeyParameter<RSAPrivateKey> get _privateKeyParams {
    final key = privateKey;
    if (key == null) {
      throw StateError("Can't use a private key operation, null given.");
    }
    return PrivateKeyParameter<RSAPrivateKey>(key);
  }
}

/// RSA encryption with PKCS#1 v1.5 or OAEP padding.
///
/// RSA can only encrypt messages shorter than the key size minus the padding
/// overhead: to encrypt more, encrypt a random AES key with RSA and the data
/// with AES-GCM (hybrid encryption).
///
/// ```dart
/// final rsa = RSA(
///   publicKey: publicKey,
///   privateKey: privateKey,
///   encoding: RSAEncoding.OAEP,
///   digest: RSADigest.SHA256,
/// );
/// ```
class RSA extends AbstractRSA implements Algorithm {
  /// Creates an RSA cipher.
  ///
  /// [publicKey] is needed to encrypt, [privateKey] to decrypt. Prefer
  /// [RSAEncoding.OAEP] for new code: PKCS#1 v1.5 encryption is exposed to
  /// padding oracle attacks.
  RSA({
    super.publicKey,
    super.privateKey,
    super.encoding,
    super.digest,
  });

  /// Encrypts [bytes] with the public key.
  ///
  /// Throws a [StateError] when no public key was given.
  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    if (publicKey == null) {
      throw StateError("Can't encrypt without a public key, null given.");
    }

    _cipher
      ..reset()
      ..init(true, _publicKeyParams);
    return Encrypted(_cipher.process(bytes));
  }

  /// Decrypts [encrypted] with the private key.
  ///
  /// Throws a [StateError] when no private key was given.
  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData}) {
    if (privateKey == null) {
      throw StateError("Can't decrypt without a private key, null given.");
    }

    _cipher
      ..reset()
      ..init(false, _privateKeyParams);
    return _cipher.process(encrypted.bytes);
  }
}

/// RSA signatures with PKCS#1 v1.5 padding (`RS256` / `RS512` in JWT terms).
///
/// See `RSAPSSSigner` for the more robust PSS padding.
///
/// ```dart
/// final signer = Signer(RSASigner(RSASignDigest.SHA256, privateKey: key));
/// ```
class RSASigner extends AbstractRSA implements SignerAlgorithm {
  /// Creates a signer hashing messages with [digest].
  ///
  /// [privateKey] is needed to sign, [publicKey] to verify.
  RSASigner(this.digest, {super.publicKey, super.privateKey})
      : _digestId = _digestIds[digest]!,
        _digestCipher = _createDigest(digest);

  /// The message digest.
  final RSASignDigest digest;

  final Uint8List _digestId;
  final Digest _digestCipher;

  /// Signs [bytes] with the private key.
  ///
  /// Throws a [StateError] when no private key was given.
  @override
  Encrypted sign(Uint8List bytes) {
    if (privateKey == null) {
      throw StateError("Can't sign without a private key, null given.");
    }

    _cipher
      ..reset()
      ..init(true, _privateKeyParams);
    return Encrypted(_cipher.process(_encode(_hash(bytes))));
  }

  /// Returns whether [signature] is a valid signature of [bytes].
  ///
  /// Returns `false`, never throws, for a malformed signature. Throws a
  /// [StateError] when no public key was given.
  @override
  bool verify(Uint8List bytes, Encrypted signature) {
    if (publicKey == null) {
      throw StateError("Can't verify without a public key, null given.");
    }

    final hash = _hash(bytes);
    _cipher
      ..reset()
      ..init(false, _publicKeyParams);

    Uint8List decoded;
    try {
      final output = Uint8List(_cipher.outputBlockSize);
      final length = _cipher.processBlock(
        signature.bytes,
        0,
        signature.bytes.length,
        output,
        0,
      );
      decoded = output.sublist(0, length);
      // A malformed signature can fail in many ways in the RSA engine and
      // the PKCS#1 decoder: all of them simply mean "invalid".
      // ignore: avoid_catches_without_on_clauses
    } catch (_) {
      return false;
    }

    final expected = _encode(hash);
    if (decoded.length == expected.length) {
      return constantTimeEquals(decoded, expected);
    }

    // Some implementations omit the NULL digest parameters in DigestInfo.
    if (decoded.length == expected.length - 2) {
      final sigOffset = decoded.length - hash.length - 2;
      final expectedOffset = expected.length - hash.length - 2;
      expected[1] -= 2;
      expected[3] -= 2;

      var nonEqual = 0;
      for (var i = 0; i < hash.length; i++) {
        nonEqual |= decoded[sigOffset + i] ^ expected[expectedOffset + i];
      }
      for (var i = 0; i < sigOffset; i++) {
        nonEqual |= decoded[i] ^ expected[i];
      }
      return nonEqual == 0;
    }

    return false;
  }

  Uint8List _hash(Uint8List bytes) {
    final hash = Uint8List(_digestCipher.digestSize);
    _digestCipher
      ..reset()
      ..update(bytes, 0, bytes.length)
      ..doFinal(hash, 0);
    return hash;
  }

  /// DER encodes the DigestInfo structure of PKCS#1 v1.5 signatures.
  Uint8List _encode(Uint8List hash) {
    final digestBytes =
        Uint8List(2 + 2 + _digestId.length + 2 + 2 + hash.length);
    var i = 0;

    digestBytes[i++] = 48;
    digestBytes[i++] = digestBytes.length - 2;
    digestBytes[i++] = 48;
    digestBytes[i++] = _digestId.length + 2;

    digestBytes.setAll(i, _digestId);
    i += _digestId.length;

    digestBytes[i++] = 5;
    digestBytes[i++] = 0;
    digestBytes[i++] = 4;
    digestBytes[i++] = hash.length;

    digestBytes.setAll(i, hash);
    return digestBytes;
  }

  static Digest _createDigest(RSASignDigest digest) {
    switch (digest) {
      case RSASignDigest.SHA256:
        return SHA256Digest();
      case RSASignDigest.SHA512:
        return SHA512Digest();
    }
  }
}

/// Padding used by [RSA] encryption.
enum RSAEncoding {
  /// PKCS#1 v1.5 padding (default, legacy).
  PKCS1,

  /// Optimal Asymmetric Encryption Padding (recommended).
  OAEP,
}

/// Digest used by [RSAEncoding.OAEP] (for both the label hash and MGF1).
enum RSADigest {
  /// SHA-1 (default, legacy).
  SHA1,

  /// SHA-256.
  SHA256,

  /// SHA-512.
  SHA512,
}

/// Message digest used by [RSASigner] and `RSAPSSSigner`.
enum RSASignDigest {
  /// SHA-256.
  SHA256,

  /// SHA-512. Crashed with a null check error in `encrypt` 5.x.
  SHA512,
}

/// DER encoded algorithm identifiers (OID TLV) of the signature digests.
final Map<RSASignDigest, Uint8List> _digestIds = {
  // 2.16.840.1.101.3.4.2.1
  RSASignDigest.SHA256: decodeHexString('0609608648016503040201'),
  // 2.16.840.1.101.3.4.2.3
  RSASignDigest.SHA512: decodeHexString('0609608648016503040203'),
};
