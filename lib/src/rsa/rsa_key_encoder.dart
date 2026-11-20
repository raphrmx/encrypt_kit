import 'dart:convert' as convert;
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/asymmetric/api.dart';

/// PEM container formats supported by [RSAKeyEncoder].
enum RSAKeyFormat {
  /// PKCS#1: `-----BEGIN RSA PUBLIC KEY-----` /
  /// `-----BEGIN RSA PRIVATE KEY-----`.
  pkcs1,

  /// PKCS#8 / X.509: `-----BEGIN PUBLIC KEY-----` /
  /// `-----BEGIN PRIVATE KEY-----`. Most widely supported.
  pkcs8,
}

/// Encodes RSA keys to PEM, readable by `RSAKeyParser`, OpenSSL, Java,
/// Python, Node.js, etc.
///
/// ```dart
/// final pair = generateRSAKeyPair();
/// final publicPem = RSAKeyEncoder.encodePublicKey(pair.publicKey);
/// final privatePem = RSAKeyEncoder.encodePrivateKey(pair.privateKey);
/// ```
abstract final class RSAKeyEncoder {
  static final _rsaEncryptionOid =
      ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.1.1');

  /// Encodes [key] as PEM in the given [format] (PKCS#8 by default).
  static String encodePublicKey(
    RSAPublicKey key, {
    RSAKeyFormat format = RSAKeyFormat.pkcs8,
  }) {
    final pkcs1 = ASN1Sequence()
      ..add(ASN1Integer(key.modulus!))
      ..add(ASN1Integer(key.publicExponent!));

    switch (format) {
      case RSAKeyFormat.pkcs1:
        return _pem('RSA PUBLIC KEY', pkcs1.encodedBytes);
      case RSAKeyFormat.pkcs8:
        final spki = ASN1Sequence()
          ..add(_algorithmIdentifier())
          ..add(ASN1BitString(pkcs1.encodedBytes));
        return _pem('PUBLIC KEY', spki.encodedBytes);
    }
  }

  /// Encodes [key] as unencrypted PEM in the given [format] (PKCS#8 by
  /// default).
  ///
  /// The output is a secret: store it in a secure location only.
  static String encodePrivateKey(
    RSAPrivateKey key, {
    RSAKeyFormat format = RSAKeyFormat.pkcs8,
  }) {
    final p = key.p!;
    final q = key.q!;
    final d = key.privateExponent!;
    final pkcs1 = ASN1Sequence()
      ..add(ASN1Integer(BigInt.zero))
      ..add(ASN1Integer(key.modulus!))
      ..add(ASN1Integer(key.publicExponent!))
      ..add(ASN1Integer(d))
      ..add(ASN1Integer(p))
      ..add(ASN1Integer(q))
      ..add(ASN1Integer(d % (p - BigInt.one)))
      ..add(ASN1Integer(d % (q - BigInt.one)))
      ..add(ASN1Integer(q.modInverse(p)));

    switch (format) {
      case RSAKeyFormat.pkcs1:
        return _pem('RSA PRIVATE KEY', pkcs1.encodedBytes);
      case RSAKeyFormat.pkcs8:
        final pkcs8 = ASN1Sequence()
          ..add(ASN1Integer(BigInt.zero))
          ..add(_algorithmIdentifier())
          ..add(ASN1OctetString(pkcs1.encodedBytes));
        return _pem('PRIVATE KEY', pkcs8.encodedBytes);
    }
  }

  static ASN1Sequence _algorithmIdentifier() => ASN1Sequence()
    ..add(_rsaEncryptionOid)
    ..add(ASN1Null());

  static String _pem(String label, Uint8List der) {
    final body = convert.base64.encode(der);
    final buffer = StringBuffer('-----BEGIN $label-----\n');
    for (var i = 0; i < body.length; i += 64) {
      final end = i + 64 < body.length ? i + 64 : body.length;
      buffer.writeln(body.substring(i, end));
    }
    buffer.write('-----END $label-----');
    return buffer.toString();
  }
}
