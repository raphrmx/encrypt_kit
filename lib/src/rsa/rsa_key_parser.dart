import 'dart:convert' as convert;
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/asymmetric/api.dart';

/// Parses PEM encoded RSA keys.
///
/// Supported formats:
/// - `-----BEGIN PUBLIC KEY-----` (X.509 SubjectPublicKeyInfo / PKCS#8)
/// - `-----BEGIN RSA PUBLIC KEY-----` (PKCS#1)
/// - `-----BEGIN PRIVATE KEY-----` (unencrypted PKCS#8)
/// - `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1)
///
/// See `RSAKeyEncoder` for the reverse operation.
class RSAKeyParser {
  static const _publicPkcs1 = 'RSA PUBLIC KEY';
  static const _publicPkcs8 = 'PUBLIC KEY';
  static const _privatePkcs1 = 'RSA PRIVATE KEY';
  static const _privatePkcs8 = 'PRIVATE KEY';

  static final _beginPattern = RegExp(r'^-----BEGIN ([A-Z0-9 ]+)-----$');

  /// Parses the PEM [key], whether it is public or private.
  ///
  /// Leading and trailing whitespace and blank lines are ignored.
  ///
  /// Throws a [FormatException] for an unsupported or malformed key.
  ///
  /// ```dart
  /// final key = RSAKeyParser().parse(pem) as RSAPublicKey;
  /// ```
  RSAAsymmetricKey parse(String key) {
    final rows = key
        .split(RegExp(r'\r\n?|\n'))
        .map((row) => row.trim())
        .where((row) => row.isNotEmpty)
        .toList();
    if (rows.isEmpty) {
      throw const FormatException('Unable to parse key, empty input.');
    }

    final header = rows.first;
    final label = _beginPattern.firstMatch(header)?.group(1);

    try {
      switch (label) {
        case _publicPkcs1:
          return _parsePublic(_parseSequence(rows));
        case _publicPkcs8:
          return _parsePublic(_pkcs8PublicSequence(_parseSequence(rows)));
        case _privatePkcs1:
          return _parsePrivate(_parseSequence(rows));
        case _privatePkcs8:
          return _parsePrivate(_pkcs8PrivateSequence(_parseSequence(rows)));
      }
    } on FormatException {
      rethrow;
      // asn1lib and the casts below fail with various error types on
      // malformed input: report all of them as a FormatException.
      // ignore: avoid_catches_without_on_clauses
    } catch (error) {
      throw FormatException('Unable to parse key: $error', header);
    }

    throw FormatException('Unable to parse key, invalid format.', header);
  }

  RSAPublicKey _parsePublic(ASN1Sequence sequence) {
    final modulus = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;

    return RSAPublicKey(modulus, exponent);
  }

  RSAPrivateKey _parsePrivate(ASN1Sequence sequence) {
    final modulus = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;

    return RSAPrivateKey(modulus, exponent, p, q);
  }

  ASN1Sequence _parseSequence(List<String> rows) {
    final keyText = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .join();

    final keyBytes = Uint8List.fromList(convert.base64.decode(keyText));
    return ASN1Parser(keyBytes).nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    final bitString = sequence.elements[1];
    final bytes = bitString.valueBytes().sublist(1);
    return ASN1Parser(Uint8List.fromList(bytes)).nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    final octetString = sequence.elements[2];
    return ASN1Parser(octetString.valueBytes()).nextObject() as ASN1Sequence;
  }
}
