import 'dart:typed_data';

import 'package:encrypt_kit/src/algorithm.dart';
import 'package:encrypt_kit/src/encrypted.dart';
import 'package:pointycastle/export.dart'
    hide Algorithm, RSASigner, SecureRandom, Signer;

/// AES block cipher in one of the [AESMode]s.
///
/// Prefer [AESMode.gcm]: it is the only mode that authenticates the data and
/// therefore detects tampering or a wrong key. With GCM, use a fresh 12 byte
/// [IV] for every message.
///
/// ```dart
/// final aes = AES(Key.fromSecureRandom(32), mode: AESMode.gcm);
/// final iv = IV.fromSecureRandom(12);
/// final encrypted = aes.encrypt(Uint8List.fromList([1, 2, 3]), iv: iv);
/// ```
class AES implements Algorithm {
  /// Creates an AES cipher.
  ///
  /// - [key]: 16, 24 or 32 bytes (AES-128, AES-192, AES-256).
  /// - [mode]: defaults to [AESMode.sic] for compatibility with `encrypt`.
  /// - [padding]: `'PKCS7'` by default, `null` for no padding. Ignored by
  ///   [AESMode.gcm], which never pads.
  AES(this.key, {this.mode = AESMode.sic, this.padding = 'PKCS7'})
      : _streamCipher = padding == null && _streamable.contains(mode)
            ? StreamCipher('AES/${_modes[mode]}')
            : null,
        _cipher = _createBlockCipher(mode, padding);

  /// The encryption key.
  final Key key;

  /// The mode of operation.
  final AESMode mode;

  /// The padding scheme name, `null` when disabled.
  final String? padding;

  final BlockCipher _cipher;
  final StreamCipher? _streamCipher;

  static BlockCipher _createBlockCipher(AESMode mode, String? padding) {
    if (mode == AESMode.gcm) {
      return GCMBlockCipher(AESEngine());
    }
    return padding != null
        ? PaddedBlockCipher('AES/${_modes[mode]}/$padding')
        : BlockCipher('AES/${_modes[mode]}');
  }

  /// Encrypts [bytes].
  ///
  /// Throws a [StateError] when [iv] is missing (all modes but ECB) and an
  /// [ArgumentError] when padding is disabled and [bytes] is not a multiple
  /// of the block size in a mode that requires it.
  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    _checkIV(iv);

    final params = _buildParams(iv, associatedData: associatedData);
    final streamCipher = _streamCipher;
    if (streamCipher != null) {
      streamCipher
        ..reset()
        ..init(true, params);
      return Encrypted(streamCipher.process(bytes));
    }

    _cipher
      ..reset()
      ..init(true, params);
    return Encrypted(_process(bytes));
  }

  /// Decrypts [encrypted].
  ///
  /// With [AESMode.gcm], throws an [InvalidCipherTextException] when the
  /// authentication tag does not match (tampered data, wrong key, IV or
  /// associated data).
  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData}) {
    _checkIV(iv);

    final params = _buildParams(iv, associatedData: associatedData);
    final streamCipher = _streamCipher;
    if (streamCipher != null) {
      streamCipher
        ..reset()
        ..init(false, params);
      return streamCipher.process(encrypted.bytes);
    }

    _cipher
      ..reset()
      ..init(false, params);
    return _process(encrypted.bytes);
  }

  void _checkIV(IV? iv) {
    if (mode != AESMode.ecb && iv == null) {
      throw StateError('IV is required.');
    }
  }

  /// GCM must always go through `process` so that the authentication tag is
  /// appended on encryption and verified on decryption. `encrypt` 5.x
  /// processed it block by block when `padding` was `null`, which silently
  /// dropped the tag and disabled authentication.
  Uint8List _process(Uint8List input) {
    if (padding != null || mode == AESMode.gcm) {
      return _cipher.process(input);
    }
    return _processBlocks(input);
  }

  Uint8List _processBlocks(Uint8List input) {
    final blockSize = _cipher.blockSize;
    if (input.lengthInBytes % blockSize != 0) {
      throw ArgumentError.value(
        input.lengthInBytes,
        'input',
        'Without padding, the input length must be a multiple of '
            '$blockSize bytes in ${mode.name} mode',
      );
    }

    final output = Uint8List(input.lengthInBytes);
    for (var offset = 0; offset < input.lengthInBytes;) {
      offset += _cipher.processBlock(input, offset, output, offset);
    }
    return output;
  }

  CipherParameters _buildParams(IV? iv, {Uint8List? associatedData}) {
    final keyParam = KeyParameter(key.bytes);

    if (mode == AESMode.ecb || iv == null) {
      return padding != null
          ? PaddedBlockCipherParameters<KeyParameter, Null>(keyParam, null)
          : keyParam;
    }

    if (mode == AESMode.gcm) {
      return AEADParameters(
        keyParam,
        128,
        iv.bytes,
        associatedData ?? Uint8List(0),
      );
    }

    final ivParams = ParametersWithIV<KeyParameter>(keyParam, iv.bytes);
    if (padding != null) {
      return PaddedBlockCipherParameters<ParametersWithIV<KeyParameter>, Null>(
        ivParams,
        null,
      );
    }
    return ivParams;
  }
}

/// AES modes of operation.
enum AESMode {
  /// Cipher Block Chaining. Not authenticated.
  cbc,

  /// 64-bit Cipher Feedback. Not authenticated.
  cfb64,

  /// Counter mode. Not authenticated.
  ctr,

  /// Electronic Code Book. INSECURE: identical blocks give identical cipher
  /// texts. Only use it for interoperability.
  ecb,

  /// 64-bit Output Feedback with GOST 28147 counter. Not authenticated.
  ofb64Gctr,

  /// 64-bit Output Feedback. Not authenticated.
  ofb64,

  /// Segmented Integer Counter (same as CTR). Not authenticated.
  sic,

  /// Galois/Counter Mode: authenticated encryption with a 128-bit tag.
  gcm,
}

const Map<AESMode, String> _modes = {
  AESMode.cbc: 'CBC',
  AESMode.cfb64: 'CFB-64',
  AESMode.ctr: 'CTR',
  AESMode.ecb: 'ECB',
  AESMode.ofb64Gctr: 'OFB-64/GCTR',
  AESMode.ofb64: 'OFB-64',
  AESMode.sic: 'SIC',
  AESMode.gcm: 'GCM',
};

const List<AESMode> _streamable = [
  AESMode.sic,
  AESMode.ctr,
];
