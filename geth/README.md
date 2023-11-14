# Yogurt
a new public blockchain network solution
fork from go-ethereum

## yogurt consensus example
genesis.json example:

```
{
  "config": {
    "chainId": 88688,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "berlinBlock": 0,
    "yogurt": {
      "period": 3,
      "epoch": 30000,
      "beaconURL":"信标链网络地址（例：127.0.0.1:37101）",
      "beaconPubKey":"信标链网络压缩公钥",
    }
  },
  "difficulty": "1",
  "gasLimit": "8000000",
  "extradata": "0x0000000000000000000000000000000000000000000000000000000000000000Ba2fbB6D4665c79f3DD63afce9114840966A210De2Ea45dc295b3B987E537125Eb51207B034731B40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "alloc": {
    "Ba2fbB6D4665c79f3DD63afce9114840966A210D": { "balance": "900000000000000000000000" },
    "e2Ea45dc295b3B987E537125Eb51207B034731B4": { "balance": "400000000000000000000000" }
  }
}
```

可以参考：geth clique network: https://geth.ethereum.org/docs/fundamentals/private-network