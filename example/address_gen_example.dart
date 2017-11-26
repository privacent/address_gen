import 'package:address_gen/address_gen.dart';

main() {
  final privK = new PrivateKey.create();
  print('Private key: ${privK.bytes}');
  final PublicKey pubK = privK.publicKey;
  print('Public key: ${pubK.bytes}');
  print('Public key x: ${pubK.point.x}');
  print('Public key y: ${pubK.point.y}');
}
