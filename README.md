# decode-starknet-calldata

A small utility to decode Starknet's transaction calldata in Rust.

## Usage

```rs
use decode_starknet_calldata::decode;
use starknet::macros::felt;

fn main() {
    // Transfer transaction calldata at https://starkscan.co/tx/0x001e18fa87db70d0a535d448959c452b739652e6c854959e90b699c572ea3e7f#overview
    let calldata = vec![
        felt!("0x1"),
        felt!("0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"),
        felt!("0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e"),
        felt!("0x0"),
        felt!("0x3"),
        felt!("0x3"),
        felt!("0x7521c84e175b5b36c3a59f8a737cbd4a4dd372d5570989770f4b99dd1a49dd"),
        felt!("0x71afd498d0011"),
        felt!("0x0"),
    ];

    let decoded = decode(&calldata).unwrap();

    // decoded: [Call { to: FieldElement { inner: 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7 }, selector: FieldElement { inner: 0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e }, calldata: [FieldElement { inner: 0x007521c84e175b5b36c3a59f8a737cbd4a4dd372d5570989770f4b99dd1a49dd }, FieldElement { inner: 0x00000000000000000000000000000000000000000000000000071afd498d0011 }, FieldElement { inner: 0x0000000000000000000000000000000000000000000000000000000000000000 }] }]
    println!("decoded: {:?}", decoded);
}
```

## Caution

The library hasn't been fully tested on whether it can fully discern a legacy calldata from a new calldata format. If you know for a certain that the format of calldata is legacy or new, directly import `decode_legacy` or `decode_new` to decode, instead of using `decode`, which first tries `decode_legacy` and then tries `decode_new` on failure.
