import 'dart:typed_data';
import 'dart:math';
import 'package:bignum/bignum.dart';
import 'package:pointycastle/pointycastle.dart';
import 'dart:collection';

/// A 'static' class that provides parameters to generate [Key]s
abstract class KeyGenParams {
  /// Length of the private key
  static const int length = 32;

  /// ECC curve parameters
  static final curveParams = new ECDomainParameters('brainpoolp256r1');

  /// Determines if [_rand] is initialized
  static bool _randInitialized = false;

  /// Random number generator to generate private key
  static final _rand = new SecureRandom("Fortuna");

  /// Random number generator to generate private key
  static SecureRandom get rand {
    if (!_randInitialized) {
      final random = new Random();
      final seeds = new Uint8List(32);
      for (int i = 0; i < 32; i++) {
        seeds[i] = random.nextInt(255);
      }
      _rand.seed(new KeyParameter(seeds));
      _randInitialized = true;
    }
    return _rand;
  }

  /// Converts given [BigInteger] [s] to bytes
  static Uint8List x9IntegerToBytes(BigInteger s, int qLength) {
    final bytes = new Uint8List.fromList(s.toByteArray());

    if (qLength < bytes.length) {
      return bytes.sublist(bytes.length - qLength);
    } else if (qLength > bytes.length) {
      return new Uint8List(qLength)..setAll(qLength - bytes.length, bytes);
    }

    return bytes;
  }
}

/// Base class for keys
abstract class Key {
  /// Key content
  Uint8List get bytes;
}

/// Public key
class PublicKey implements Key {
  /// Key content
  final Uint8List bytes;

  /// Creates [PublicKey] from constituent [bytes]
  PublicKey(this.bytes);

  /// Creates [PublicKey] from give [ECPoint] [point]
  factory PublicKey.fromPoint(ECPoint point) {
    if (point.isInfinity)
      throw new ArgumentError.value(point, 'point', 'Shall not be infinite!');

    final int qLength = point.x.byteLength;
    Uint8List xBytes =
        KeyGenParams.x9IntegerToBytes(point.x.toBigInteger(), qLength);
    Uint8List yBytes =
        KeyGenParams.x9IntegerToBytes(point.y.toBigInteger(), qLength);
    final bytes = new Uint8List(xBytes.length + yBytes.length);
    bytes.setAll(0, xBytes);
    bytes.setAll(xBytes.length, yBytes);
    return new PublicKey(bytes);
  }

  /// Returns the [ECPoint] of this [PublicKey]
  ECPoint get point {
    final int expectedLength =
        (KeyGenParams.curveParams.curve.fieldSize + 7) ~/ 8;
    if (bytes.length != (2 * expectedLength)) {
      throw new Exception("Incorrect length for uncompressed encoding");
    }

    final xBytes = new UnmodifiableListView(bytes.take(expectedLength));
    final yBytes = new UnmodifiableListView(bytes.skip(expectedLength));

    final x = new BigInteger.fromBytes(1, xBytes);
    final y = new BigInteger.fromBytes(1, yBytes);

    return KeyGenParams.curveParams.curve.createPoint(x, y, false);
  }
}

/// Private key
class PrivateKey implements Key {
  /// Key content
  final Uint8List bytes;

  /// Creates [PrivateKey] from constituent [bytes]
  PrivateKey(this.bytes);

  /// Creates a new random public key
  factory PrivateKey.create() {
    final BigInteger n = KeyGenParams.curveParams.n;
    final int nBitLength = n.bitLength();

    // The private key
    BigInteger d;

    do {
      d = KeyGenParams.rand.nextBigInteger(nBitLength);
    } while (d == BigInteger.ZERO || (d >= n));

    final bytes = new Uint8List.fromList(d.toByteArray());

    return new PrivateKey(bytes);
  }

  /// Get public key for this private key
  PublicKey get publicKey {
    final ECPoint q =
        KeyGenParams.curveParams.G * new BigInteger.fromBytes(1, bytes);
    return new PublicKey.fromPoint(q);
  }

  /// Returns the [KeyPair] for this [PrivateKey]
  KeyPair get pair => new KeyPair(publicKey, this);
}

/// Public and private key pair
class KeyPair {
  /// Private key
  final PrivateKey privateKey;

  /// Public key
  final PublicKey publicKey;

  /// Contracts a [KeyPair] from given [publicKey] and [privateKey]
  KeyPair(this.publicKey, this.privateKey);

  /// Creates a new random [KeyPair]
  factory KeyPair.create() {
    final privateKey = new PrivateKey.create();
    final publicKey = privateKey.publicKey;
    return new KeyPair(publicKey, privateKey);
  }
}
