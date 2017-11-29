import 'package:address_gen/address_gen.dart';

main() {
  final walletKeys = new WalletKeys.createSeparate();
  print(walletKeys);
  final walletAddr = walletKeys.address;
  print(walletAddr);

  {
    final r = KeyGenParams.rand.nextBigInteger(255);
    final int o = 0;
    final otsa = walletAddr.oneTimeStealthAddress(r, o);
    print(otsa);

    final rPoint = new PublicKey.fromPoint(KeyGenParams.curveParams.G * r);
    print(walletKeys.isMyOneTimeStealthAddress(otsa, rPoint, o));
  }
}
