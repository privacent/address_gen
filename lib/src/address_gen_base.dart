import 'dart:typed_data';
import 'dart:math';
import 'package:bignum/bignum.dart';
import 'package:pointycastle/pointycastle.dart';
import 'dart:collection';
import 'package:base58check/base58.dart';
import 'package:collection/collection.dart';

/// A 'static' class that provides parameters to generate [Key]s
abstract class KeyGenParams {
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

  static final Digest sha3_256 = new Digest('SHA-3/256');

  static const String base58Alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  static final Base58Codec base58 = const Base58Codec(base58Alphabet);
}

/// Base class for keys
abstract class Key {
  /// Key content
  UnmodifiableListView<int> get bytes;
}

/// Private key
class PrivateKey implements Key {
  /// Key content
  final UnmodifiableListView<int> bytes;

  /// Creates [PrivateKey] from constituent [bytes]
  PrivateKey(this.bytes) {
    if (bytes.length != length)
      throw new ArgumentError.value(
          bytes, 'bytes', 'Private key must be $length bytes long!');
  }

  /// Creates a new random public key
  factory PrivateKey.create() {
    final BigInteger n = KeyGenParams.curveParams.n;
    final int nBitLength = n.bitLength() - 1;

    // The private key
    BigInteger d;

    do {
      d = KeyGenParams.rand.nextBigInteger(nBitLength);
    } while (d == BigInteger.ZERO || (d >= n));

    final bytes = new Uint8List.fromList(d.toByteArray());

    return new PrivateKey(new UnmodifiableListView<int>(bytes));
  }

  /// Get public key for this private key
  PublicKey get publicKey {
    final ECPoint q =
        KeyGenParams.curveParams.G * new BigInteger.fromBytes(1, bytes);
    return new PublicKey.fromPoint(q);
  }

  BigInteger get asBigInteger => new BigInteger.fromBytes(1, bytes);

  /// Returns the [KeyPair] for this [PrivateKey]
  KeyPair get pair => new KeyPair(publicKey, this);

  String toString() => bytes.toString();

  /// Length of the private key
  static const int length = 32;
}

/// Public key
class PublicKey implements Key {
  /// Key content
  final UnmodifiableListView<int> bytes;

  /// Creates [PublicKey] from constituent [bytes]
  PublicKey(Iterable<int> bytes)
      : bytes = bytes is UnmodifiableListView<int>
            ? bytes
            : new UnmodifiableListView<int>(bytes) {
    if (bytes.length != length)
      throw new ArgumentError.value(
          bytes, 'bytes', 'Public key must be $length bytes long!');
  }

  /// Creates [PublicKey] from give [ECPoint] [point]
  factory PublicKey.fromPoint(ECPoint point) {
    return new PublicKey(pointToBytes(point));
  }

  /// Returns the [ECPoint] of this [PublicKey]
  ECPoint get point {
    final int expectedLength =
        (KeyGenParams.curveParams.curve.fieldSize + 7) ~/ 8;
    if (bytes.length != (expectedLength + 1)) {
      throw new Exception("Incorrect length for uncompressed encoding");
    }

    final xBytes =
        new BigInteger.fromBytes(1, bytes.take(expectedLength).toList());
    final yTilde = bytes.last & 1;

    return KeyGenParams.curveParams.curve.decompressPoint(yTilde, xBytes);
  }

  String toString() => bytes.toString();

  bool operator ==(other) {
    if (other is PublicKey) {
      return const IterableEquality().equals(bytes, other.bytes);
    } else if (other is ECPoint) {
      return point == other;
    } else if (other is Iterable<int>) {
      return const IterableEquality().equals(bytes, other);
    }

    return false;
  }

  /// Length of the private key
  static const int length = 33;

  static List<int> pointToBytes(ECPoint point) {
    if (point.isInfinity)
      throw new ArgumentError.value(point, 'point', 'Shall not be infinite!');

    final int qLength = point.x.byteLength;

    final Uint8List xBytes =
        KeyGenParams.x9IntegerToBytes(point.x.toBigInteger(), qLength);

    final bytes = new List<int>.filled(xBytes.length + 1, 0, growable: true);

    bytes.setAll(0, xBytes);

    if (point.y.toBigInteger().testBit(0)) {
      bytes[bytes.length - 1] = 0x01;
    }

    return bytes;
  }
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

  String toString() {
    final sb = new StringBuffer();
    sb.writeln('Private key: $privateKey');
    sb.writeln('Public key: $publicKey');
    return sb.toString();
  }
}

/// A wallet capable of viewing transactions on the blockchain
abstract class ViewableWallet {
  /// Private view key
  PrivateKey get viewKey;

  /// Public spend key
  PublicKey get spendPubKey;

  /// Returns if the given one time stealth address [otsa] belongs to this
  /// wallet
  bool isMyOneTimeStealthAddress(PublicKey otsa, PublicKey r, int outputIndex) {
    final ECPoint d = r.point * viewKey.asBigInteger;
    final Uint8List dBytes =
        new Uint8List.fromList(PublicKey.pointToBytes(d)..add(outputIndex));
    final Uint8List dHash = KeyGenParams.sha3_256.process(dBytes);
    final ECPoint f =
        KeyGenParams.curveParams.G * new BigInteger.fromBytes(1, dHash);
    return new PublicKey.fromPoint(f + spendPubKey.point) == otsa;
  }
}

/// A wallet key is a collection of a private spend key and a private view key
class WalletKeys extends Object with ViewableWallet {
  /// Private spend key
  final PrivateKey spendKey;

  /// Private view key
  final PrivateKey viewKey;

  WalletKeys(this.spendKey, this.viewKey);

  /// Creates [WalletKeys] where spend and view key cannot be derived from the
  /// other
  factory WalletKeys.createSeparate() {
    final PrivateKey spendKey = new PrivateKey.create();
    final PrivateKey viewKey = new PrivateKey.create();
    return new WalletKeys(spendKey, viewKey);
  }

  /// Public spend key
  PublicKey get spendPubKey => spendKey.publicKey;

  /// Public view key
  PublicKey get viewPubKey => viewKey.publicKey;

  /// Spend key pair
  KeyPair get spendPair => spendKey.pair;

  /// View key pair
  KeyPair get viewPair => viewKey.pair;

  /// Returns [WalletAddress] of this wallet
  WalletAddress get address =>
      new WalletAddress.fromPubKeys(spendPubKey, viewPubKey);

  String toString() {
    final sb = new StringBuffer();
    sb.writeln('Spend key:');
    sb.writeln(spendPair);
    sb.writeln('View key:');
    sb.writeln(viewPair);
    return sb.toString();
  }
}

/// Model to hold wallet addresses
class WalletAddress {
  final UnmodifiableListView<int> bytes;

  /// Creates [PrivateKey] from constituent [bytes]
  WalletAddress(this.bytes) {
    if (bytes.length != expectedLength)
      throw new ArgumentError.value(
          bytes, 'bytes', 'Wallet address must be $expectedLength bytes long!');

    if (bytes.first != expectedNetworkByte)
      throw new ArgumentError.value(bytes, 'bytes', 'Invalid network byte!');

    if (!validateChecksum())
      throw new ArgumentError.value(bytes, 'bytes', 'Checksum mismatch!');
  }

  /// Creates [WalletAddress] from Base58 encoded address format
  factory WalletAddress.fromBase58(String base58) {
    final List<int> bytes = KeyGenParams.base58.decode(base58);
    return new WalletAddress(new UnmodifiableListView<int>(bytes));
  }

  /// Creates [WalletAddress] from spend and view [PublicKey]
  factory WalletAddress.fromPubKeys(
      PublicKey spendPubKey, PublicKey viewPubKey) {
    final bytes = new Uint8List(expectedLength);
    bytes[0] = expectedNetworkByte; // Network byte
    bytes.setAll(spendStart, spendPubKey.bytes);
    bytes.setAll(viewStart, viewPubKey.bytes);
    fillChecksum(bytes);
    return new WalletAddress(new UnmodifiableListView<int>(bytes));
  }

  /// Returns spend [PublicKey]
  PublicKey get spendPubKey =>
      new PublicKey(bytes.skip(spendStart).take(PublicKey.length));

  /// Returns view [PublicKey]
  PublicKey get viewPubKey =>
      new PublicKey(bytes.skip(viewStart).take(PublicKey.length));

  /// Computes onetime stealth address to this wallet
  PublicKey oneTimeStealthAddress(BigInteger r, int outputIndex) {
    final ECPoint d = viewPubKey.point * r;
    final Uint8List dBytes =
        new Uint8List.fromList(PublicKey.pointToBytes(d)..add(outputIndex));
    final Uint8List dHash = KeyGenParams.sha3_256.process(dBytes);
    final ECPoint f =
        KeyGenParams.curveParams.G * new BigInteger.fromBytes(1, dHash);
    return new PublicKey.fromPoint(f + spendPubKey.point);
  }

  /// Network byte of the [WalletAddress]
  int get networkByte => bytes[0];

  /// Checksum part of the [WalletAddress]
  Iterable<int> get checksum => bytes.skip(checksumStart);

  /// Validates if the checksum matches
  bool validateChecksum() {
    final content = new Uint8List.fromList(bytes.sublist(0, checksumStart));
    final Uint8List digest = KeyGenParams.sha3_256.process(content);
    return const IterableEquality()
        .equals(bytes.skip(checksumStart), digest.take(4));
  }

  /// Returns Base58 representation of the [WalletAddress]
  String get base58 => KeyGenParams.base58.encode(bytes);

  /// Pretty prints content of [WalletAddress]
  String toString() {
    final sb = new StringBuffer();

    sb.writeln('Network byte: $networkByte');
    sb.writeln('Spend public key: $spendPubKey');
    sb.writeln('View public key: $viewPubKey');
    sb.writeln('Checksum: $checksum');

    return sb.toString();
  }

  /// Expected length of [WalletAddress] in raw bytes
  static const int expectedLength = (PublicKey.length * 2) + 1 + 4;

  /// Network byte for [WalletAddress]
  static const int expectedNetworkByte = 0x55;

  /// Start position of Spend public key in [WalletAddress] as raw bytes
  static const int spendStart = 1;

  /// Start position of View public key in [WalletAddress] as raw bytes
  static const int viewStart = 1 + PublicKey.length;

  /// Start position of checksum in [WalletAddress] as raw bytes
  static const int checksumStart = (PublicKey.length * 2) + 1;

  static const int checksumLength = 4;

  /// Fills checksum for the given [WalletAddress] as raw bytes
  static void fillChecksum(Uint8List bytes) {
    final content = new Uint8List.fromList(bytes.sublist(0, checksumStart));
    final Uint8List digest = KeyGenParams.sha3_256.process(content);
    bytes.setAll(checksumStart, digest.take(4));
  }
}
