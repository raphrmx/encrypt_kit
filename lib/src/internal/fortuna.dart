import 'package:encrypt_plus/src/secure_random.dart' as encrypt;
import 'package:pointycastle/api.dart' show KeyParameter, SecureRandom;
import 'package:pointycastle/random/fortuna_random.dart';

/// Creates a PointyCastle [SecureRandom] seeded from the platform CSPRNG.
///
/// PointyCastle generators (RSA key generation, PSS salts) need their own
/// random source: this one is a Fortuna generator seeded with 32 bytes from
/// `Random.secure()`.
SecureRandom createSeededRandom() =>
    FortunaRandom()..seed(KeyParameter(encrypt.SecureRandom(32).bytes));
