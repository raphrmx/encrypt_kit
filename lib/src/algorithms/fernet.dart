import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:encrypt_plus/src/algorithm.dart';
import 'package:encrypt_plus/src/algorithms/aes.dart';
import 'package:encrypt_plus/src/encrypted.dart';
import 'package:encrypt_plus/src/utils.dart';
import 'package:pointycastle/api.dart' show KeyParameter;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/macs/hmac.dart';

/// [Fernet](https://github.com/fernet/spec/blob/master/Spec.md) symmetric
/// authenticated encryption (AES-128-CBC + HMAC-SHA256), compatible with the
/// Python `cryptography` package.
///
/// ```dart
/// final fernet = Fernet(Key.fromBase64(urlSafeBase64Key));
/// final token = Encrypter(fernet).encrypt('secret').base64Url;
/// ```
class Fernet implements Algorithm {
  /// Creates a Fernet cipher from a 32 byte [key]: the first 16 bytes sign,
  /// the last 16 bytes encrypt.
  ///
  /// [clock] can be overridden for tests.
  ///
  /// Throws a [StateError] when [key] is not 32 bytes long.
  Fernet(Key key, {Clock? clock})
      : _signKey = _checkKey(key).bytes.sublist(0, 16),
        _encryptionKey = Key(Uint8List.fromList(key.bytes.sublist(16))),
        _clock = clock ?? const Clock();

  static const _maxClockSkew = 60;
  static const _version = 0x80;
  static const _headerLength = 1 + 8 + 16;
  static const _hmacLength = 32;
  static const _blockSize = 16;

  final Uint8List _signKey;
  final Key _encryptionKey;
  final Clock _clock;

  static Key _checkKey(Key key) {
    if (key.length != 32) {
      throw StateError('Fernet key must be 32 url-safe base64-encoded bytes.');
    }
    return key;
  }

  /// Encrypts [bytes] into a Fernet token.
  ///
  /// [iv] is generated when omitted, which is what you want outside tests.
  /// [associatedData] is not supported by Fernet and is ignored.
  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    final currentTime = _clock.now().millisecondsSinceEpoch ~/ 1000;
    return Encrypted(
      _encryptFromParts(bytes, currentTime, iv ?? IV.fromSecureRandom(16)),
    );
  }

  /// Decrypts a Fernet token.
  ///
  /// When [ttl] (in seconds) is given, tokens older than [ttl] are rejected.
  /// [iv] must be `null`: it is read from the token.
  ///
  /// Throws a [StateError] (`Invalid token`) when the token is malformed,
  /// expired, from the future or its HMAC does not match.
  @override
  Uint8List decrypt(
    Encrypted encrypted, {
    IV? iv,
    Uint8List? associatedData,
    int? ttl,
  }) {
    final data = encrypted.bytes;
    final cipherTextLength = data.length - _headerLength - _hmacLength;
    if (data.isEmpty ||
        data.first != _version ||
        cipherTextLength <= 0 ||
        cipherTextLength % _blockSize != 0) {
      throw StateError('Invalid token');
    }

    final ts = extractTimestamp(data);
    final now = _clock.now().millisecondsSinceEpoch ~/ 1000;
    if (ttl != null && ts + ttl < now) {
      throw StateError('Invalid token');
    }
    if (now + _maxClockSkew < ts) {
      throw StateError('Invalid token');
    }
    _verifySignature(data);
    if (iv != null) {
      throw StateError('IV must be infered from token');
    }

    final tokenIV = IV(Uint8List.fromList(data.sublist(9, _headerLength)));
    final cipherText = Encrypted(
      Uint8List.fromList(data.sublist(_headerLength, data.length - 32)),
    );
    return AES(_encryptionKey, mode: AESMode.cbc)
        .decrypt(cipherText, iv: tokenIV);
  }

  /// Returns the Unix timestamp (in seconds) stored in the token [data].
  int extractTimestamp(Uint8List data) {
    if (data.length < 9) {
      throw StateError('Invalid token');
    }
    final bdata = ByteData.sublistView(data, 1, 9);
    // dart2js has no 64-bit integers: combine two 32-bit halves, which is
    // exact for any realistic timestamp.
    final hi = bdata.getUint32(0);
    final low = bdata.getUint32(4);
    return hi * 0x100000000 + low;
  }

  void _verifySignature(Uint8List data) {
    final signed = Uint8List.sublistView(data, 0, data.length - _hmacLength);
    final digest = Uint8List.sublistView(data, data.length - _hmacLength);
    if (!constantTimeEquals(digest, _hmac(signed))) {
      throw StateError('Invalid token');
    }
  }

  Uint8List _hmac(Uint8List input) =>
      (HMac(SHA256Digest(), 64)..init(KeyParameter(_signKey))).process(input);

  Uint8List _encryptFromParts(Uint8List bytes, int currentTime, IV iv) {
    final cipherText =
        AES(_encryptionKey, mode: AESMode.cbc).encrypt(bytes, iv: iv);

    final timestamp = ByteData(8)
      ..setUint32(0, currentTime ~/ 0x100000000)
      ..setUint32(4, currentTime % 0x100000000);

    final parts = Uint8List.fromList([
      _version,
      ...timestamp.buffer.asUint8List(),
      ...iv.bytes,
      ...cipherText.bytes,
    ]);
    return Uint8List.fromList([...parts, ..._hmac(parts)]);
  }
}
