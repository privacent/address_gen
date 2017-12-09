# address_gen

Address and private/public key generator for PrivaCent

## Usage

```dart
import 'package:address_gen/address_gen.dart';

main() {
  final privK = new PrivateKey.create();
  print('Private key: ${privK.bytes}');
  final PublicKey pubK = privK.publicKey;
  print('Public key: ${pubK.bytes}');
  print('Public key x: ${pubK.point.x}');
  print('Public key y: ${pubK.point.y}');
}
```

# TODO

+ [X] Private key generation
+ [X] Public key extraction
+ [X] Wallet keys
+ [X] Generate wallet address from Spend and View public keys
+ [ ] Derive View private key from Spend private key
+ [ ] One-time stealth addresses
+ [ ] Sub-addresses
