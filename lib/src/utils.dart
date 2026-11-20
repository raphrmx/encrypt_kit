import 'dart:typed_data';

/// Decodes a hexadecimal (base 16) string into bytes.
///
/// Both lower and upper case digits are accepted.
///
/// Throws a [FormatException] when [input] has an odd length or contains a
/// non hexadecimal character. Versions of `encrypt` before 6.0.0 silently
/// dropped the last character of an odd length input in release builds.
///
/// ```dart
/// decodeHexString('cafe'); // [202, 254]
/// ```
Uint8List decodeHexString(String input) {
  if (input.length.isOdd) {
    throw FormatException('Hex input needs to be an even length.', input);
  }

  final output = Uint8List(input.length ~/ 2);
  for (var i = 0; i < output.length; i++) {
    final byte = int.tryParse(input.substring(i * 2, i * 2 + 2), radix: 16);
    if (byte == null) {
      throw FormatException('Invalid hex character.', input, i * 2);
    }
    output[i] = byte;
  }
  return output;
}

/// Encodes [bytes] as a lower case hexadecimal string.
String encodeHexString(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

/// Compares [a] and [b] in a time that only depends on their lengths.
///
/// Must be used to compare secrets such as MACs or signatures to avoid
/// timing side channels.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }

  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
