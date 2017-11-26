import 'package:address_gen/address_gen.dart';

main() {
  final walletKeys = new WalletKeys.createSeparate();
  print(walletKeys);
  print(walletKeys.address);
}
