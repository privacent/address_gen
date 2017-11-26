# address_gen

Address and private/public key generator for PrivaCent

Created from templates made available by Stagehand under a BSD-style
[license](https://github.com/dart-lang/stagehand/blob/master/LICENSE).

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

+ [ ] Derive View private key from Spend private key
+ [ ] Generate wallet address from Spend and View public keys
