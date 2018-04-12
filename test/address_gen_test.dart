import 'package:test/test.dart';
import 'package:bignum/bignum.dart';
import 'package:pointycastle/pointycastle.dart' hide PrivateKey, PublicKey;

import 'package:address_gen/address_gen.dart';

void main() {
  group('Private key', () {
    test('Length', () {
      final privK = new PrivateKey.create();
      expect(privK.bytes.length, PrivateKey.length);
    });
  });

  group('Public key', () {
    setUp(() {});

    test('Recover point', () {
      final privK = new PrivateKey.create();

      final ECPoint q =
          KeyGenParams.curveParams.G * new BigInteger.fromBytes(1, privK.bytes);

      final PublicKey pubK = privK.publicKey;

      expect(q, pubK.point);
    });
  });

  group('WalletAddress', () {
    setUp(() {});

    test('Public keys', () {
      final walletKeys = new WalletKeys.createSeparate();
      final address = walletKeys.address;

      expect(walletKeys.spendPubKey.bytes, address.spendPubKey.bytes);
      expect(walletKeys.viewPubKey.bytes, address.viewPubKey.bytes);
    });
  });
}
