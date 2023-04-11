# A very basic no-std / no-alloc Matter device implementation

Just a personal project for learning purposes. The code is just hacked together, lacking proper error handling etc.

A lot is missing from this.

You can comission the device via the Chiptool Android app and toggle a light. That's it.
(Use chiptool from https://github.com/mfucci/node-matter/tree/main/matter-test-apk)

Use the "PROVISION CHIP DEVICE WITH WIFI", "INPUT DEVICE ADDRESS" and enter the IP address.

**Provisioning the device**:

```
chip-tool pairing ethernet 222 20202021 3940 192.168.2.125 5540
```

QR Code URL
https://project-chip.github.io/connectedhomeip/qrcode.html?data=MT%3A-24J0AFN00KA0648G00

# TODO

- Implement CASE resumption
- Improve error handling
- Don't hardcode keypair
- Implement ACK / Retransmission
- Implement persistence
- Add certificate validation
- Add support for brightness level
- Add more nodes
- Implement ACL
- Add IPv6 support
- ...

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
