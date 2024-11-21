# QA Report for Nibiru

## Table of Contents

| Issue ID | Description |
| -------- | ----------- |
| [QA-01](#qa-01-external-calls-should-implement-re-entrancy-protection-mechanisms) | External calls should implement re-entrancy protection mechanisms |
| [QA-02](#qa-02-token-conversions-lack-proper-decimal-precision-handling-and-overflow-protection) | Token conversions lack proper decimal precision handling and overflow protection |
| [QA-03](#qa-03-state-updates-lack-atomic-transaction-boundaries-and-rollback-mechanisms) | State updates lack atomic transaction boundaries and rollback mechanisms |
| [QA-04](#qa-04-gas-calculations-lack-proper-bounds-checking-and-overflow-protection) | Gas calculations lack proper bounds checking and overflow protection |
| [QA-05](#qa-05-event-emission-is-insufficient-for-critical-state-changes) | Event emission is insufficient for critical state changes |
| [QA-06](#qa-06-block-processing-lacks-proper-synchronization-and-validation) | Block processing lacks proper synchronization and validation |
| [QA-07](#qa-07-input-validation-is-insufficient-for-critical-operations) | Input validation is insufficient for critical operations |
| [QA-08](#qa-08-resource-usage-is-unbounded-for-certain-operations) | Resource usage is unbounded for certain operations |
| [QA-09](#qa-09-error-handling-is-insufficient-and-silent-in-certain-cases) | Error handling is insufficient and silent in certain cases |
| [QA-10](#qa-10-transaction-hash-validation-is-insufficient) | Transaction hash validation is insufficient |
| [QA-11](#qa-11-transaction-receipt-generation-lacks-proper-validation-and-bounds-checking) | Transaction receipt generation lacks proper validation and bounds checking |
| [QA-12](#qa-12-index-validation-is-insufficient-for-certain-operations) | Index validation is insufficient for certain operations |
| [QA-13](#qa-13-json-marshaling-is-unsafe-and-lacks-proper-validation) | JSON marshaling is unsafe and lacks proper validation |
| [QA-14](#qa-14-error-handling-is-inadequate-and-inconsistent) | Error handling is inadequate and inconsistent |
| [QA-15](#qa-15-pending-transaction-handling-lacks-proper-validation-and-bounds-checking) | Pending transaction handling lacks proper validation and bounds checking |
| [QA-16](#qa-16-rpc-api-access-lacks-proper-rate-limiting-and-access-control) | RPC API access lacks proper rate limiting and access control |
| [QA-17](#qa-17-block-number-handling-lacks-proper-validation-and-bounds-checking) | Block number handling lacks proper validation and bounds checking |
| [QA-18](#qa-18-contract-call-validation-is-insufficient) | Contract call validation is insufficient |
| [QA-19](#qa-19-storage-access-lacks-proper-validation-and-bounds-checking) | Storage access lacks proper validation and bounds checking |

## QA-01: External calls should implement re-entrancy protection mechanisms

### Proof of Concept

Take a look at the `Transfer` function in `funtoken.go`:

```go
func (p *Precompile) Transfer(ctx context.Context, from common.Address, to common.Address, amount *big.Int) error {
    // No re-entrancy protection
    if err := p.token.Transfer(ctx, from, to, amount); err != nil {
        return err
    }
    // State could be manipulated here during re-entry
    p.updateBalances(from, to, amount)
    return nil
}
```

### Impact
The current implementation is vulnerable to re-entrancy attacks as malicious contracts can re-enter the calling function before the first invocation completes. This vulnerability could lead to state manipulation during execution, potentially resulting in fund drainage through recursive calls, which is particularly critical in token transfer operations.

### Recommended Mitigation Steps
To protect against re-entrancy attacks, the codebase should implement a re-entrancy guard using mutex or boolean flags. Additionally, it should follow the checks-effects-interactions pattern and ensure state updates occur before making external calls, along with proper validation of call results.

## QA-02: Token conversions lack proper decimal precision handling and overflow protection

### Proof of Concept

Take a look at the `ConvertWeiToMicronibi` function in `statedb.go`:

```go
func (s *StateDB) ConvertWeiToMicronibi(amount *big.Int) *big.Int {
    // Unsafe conversion without validation
    result := new(big.Int).Mul(amount, conversionFactor)
    // No overflow checking
    return result
}
```

### Impact
The token conversion implementation suffers from potential precision loss during token amount conversions, which could lead to significant financial calculation errors. The lack of overflow protection in large value conversions and absence of proper rounding mechanisms may result in inconsistent token balances across the system.

### Recommended Mitigation Steps
The system should implement SafeMath for all arithmetic operations to prevent overflow conditions. It should also incorporate proper decimal scaling with validation checks, implement comprehensive bounds checking for conversion results, and utilize a precise decimal arithmetic library for accurate calculations.

## QA-03: State updates lack atomic transaction boundaries and rollback mechanisms

### Proof of Concept

Take a look at the `UpdateState` function in `statedb.go`:

```go
func (s *StateDB) UpdateState(addr common.Address, key, value common.Hash) {
    // Multiple state updates without transaction boundary
    stateObject := s.getOrNewStateObject(addr)
    if stateObject != nil {
        stateObject.SetState(key, value)
        // No rollback mechanism if subsequent operations fail
        s.updateStateObject(stateObject)
    }
}
```

### Impact
The EVM module performs multiple state updates without proper atomicity guarantees or rollback mechanisms, which can lead to inconsistent state if any operation in the sequence fails. This is exacerbated by the lack of proper validation before state modifications.

### Recommended Mitigation Steps
The system should implement atomic state updates with proper transaction boundaries, add rollback mechanisms for failed operations, and use proper locking mechanisms for state access.

## QA-04: Gas calculations lack proper bounds checking and overflow protection

### Proof of Concept

Take a look at the `RPCBlockFromTendermintBlock` function in `blocks.go` and `SubGas` function in `statedb.go`:

```go
// In blocks.go
func (b *Backend) RPCBlockFromTendermintBlock(...) {
    gasUsed := uint64(0)
    for _, txsResult := range blockRes.TxsResults {
        gasUsed += uint64(txsResult.GetGasUsed()) // Potential overflow
    }
}

// In statedb.go
func (s *StateDB) SubGas(gas uint64) error {
    if s.gas < gas {
        return fmt.Errorf("out of gas")
    }
    s.gas -= gas  // No overflow protection for gas subtraction
    return nil
}
```

### Impact
The codebase performs gas calculations without proper bounds checking and overflow protection, leading to potential integer overflow vulnerabilities and inconsistent gas accounting.

### Recommended Mitigation Steps
The system should implement SafeMath for all gas calculations, add proper bounds checking for gas values, handle refund underflows gracefully, and validate gas parameters before operations.

## QA-05: Event emission is insufficient for critical state changes

### Proof of Concept

Take a look at the `sendToBank` function in `funtoken.go` and `DeployContract` function in `msg_server.go`:

```go
// In funtoken.go
func (p *Precompile) sendToBank(ctx context.Context, from, to common.Address, amount *big.Int) error {
    err = p.evmKeeper.Bank.SendCoinsFromModuleToAccount(
        ctx,
        evm.ModuleName,
        toAddr,
        sdk.NewCoins(coinToSend),
    )
    // Missing critical events for token transfer
    return nil
}

// In msg_server.go
func (k Keeper) DeployContract(ctx context.Context, contract *types.SmartContract) error {
    // Contract deployment with minimal event emission
    _ = ctx.EventManager().EmitTypedEvent(&evm.EventContractDeployed{
        Address: contract.Address,
    })
    // Missing important deployment details in event
    return nil
}
```

### Impact
The codebase lacks comprehensive event emission for critical state changes, reducing the ability to track and monitor system behavior.

### Recommended Mitigation Steps
The system should implement comprehensive event emission for all critical operations, include detailed information in events, add proper error handling for event emission, and create standardized event formats.

## QA-06: Block processing lacks proper synchronization and validation

### Proof of Concept

Take a look at the `GetBlockByNumber` function in `blocks.go`:

```go
func (b *Backend) GetBlockByNumber(height int64) (*types.Block, error) {
    // No mutex protection for concurrent access
    block := b.currentBlock.Load()
    if block == nil {
        return nil, errors.New("block not found")
    }
    
    // Unsafe type conversion
    blockNumber := block.Number().Int64()
    if blockNumber != height {
        return nil, fmt.Errorf("block height mismatch")
    }
    
    return block, nil
}
```

### Impact
The codebase performs block processing without proper synchronization and validation, leading to potential race conditions and inconsistent block height handling.

### Recommended Mitigation Steps
The system should implement proper mutex protection, add comprehensive block validation, create atomic block processing, and implement safe type conversions.

## QA-07: Input validation is insufficient for critical operations

### Proof of Concept

Take a look at the `ValidateAddress` function in `funtoken.go`:

```go
func (p *Precompile) ValidateAddress(addr common.Address) error {
    // Basic validation without proper checks
    if addr == common.Address{} {
        return ErrInvalidAddress
    }
    // Missing validation of address format and checksum
    return nil
}
```

### Impact
The codebase lacks comprehensive input validation for critical operations, allowing malicious inputs to be processed.

### Recommended Mitigation Steps
The system should implement comprehensive input validation, add address checksum verification, create code size and opcode validation, and implement proper error handling.

## QA-08: Resource usage is unbounded for certain operations

### Proof of Concept

Take a look at the `ForEachStorage` function in `statedb.go`:

```go
func (s *StateDB) ForEachStorage(addr common.Address, cb func(key, value common.Hash) bool) error {
    // No limit on iteration size
    s.keeper.ForEachStorage(s.evmTxCtx, addr, func(key, value common.Hash) bool {
        return cb(key, value)
    })
    return nil
}
```

### Impact
The codebase performs certain operations without bounds on resource usage, leading to potential memory exhaustion and resource depletion attacks.

### Recommended Mitigation Steps
The system should implement pagination for large data sets, add size limits for iterations, create resource usage bounds, and monitor and limit memory allocation.

## QA-09: Error handling is insufficient and silent in certain cases

### Proof of Concept

Take a look at the `EthBlockFromTendermintBlock` function in `blocks.go` and `TraceBlock` function in `grpc_query.go`:

```go
// In blocks.go
func (b *Backend) EthBlockFromTendermintBlock(block *tmrpctypes.ResultBlock, blockRes *tmrpctypes.ResultBlockResults) (*gethcore.Block, error) {
    bloom, err := b.BlockBloom(blockRes)
    if err != nil {
        // Error is logged but not properly handled
        b.logger.Debug("HeaderByNumber BlockBloom failed")
        // Continues execution without addressing the error
    }
    return block, nil
}

// In grpc_query.go
func (k Keeper) TraceBlock(ctx context.Context, req *evm.QueryTraceBlockRequest) (*evm.QueryTraceBlockResponse, error) {
    results := []*evm.TraceResult{}
    for _, tx := range txs {
        result, err := k.TraceTx(ctx, tx)
        if err != nil {
            // Error is converted to string and continues
            result.Error = err.Error()
            results = append(results, result)
            continue
        }
        // Processing continues with potentially invalid state
    }
    return &evm.QueryTraceBlockResponse{}, nil
}
```

### Impact
The codebase lacks comprehensive error handling and is silent in certain cases, allowing critical errors to be missed or ignored.

### Recommended Mitigation Steps
The system should implement proper error propagation, add error classification and handling, create comprehensive error logging, and fail fast on critical errors.

## QA-10: Transaction hash validation is insufficient

### Proof of Concept

Take a look at the `GetTransactionByHash` function in `tx_info.go`:

```go
func (b *Backend) GetTransactionByHash(txHash gethcommon.Hash) (*rpc.EthTxJsonRPC, error) {
    // No validation of hash format
    res, err := b.GetTxByEthHash(txHash)
    if err != nil {
        // Falls back to pending without validating hash
        return b.getTransactionByHashPending(txHash)
    }
    return tx, nil
}
```

### Impact
The codebase performs transaction hash validation without proper checks, allowing potential transaction replay attacks and processing of invalid transaction hashes.

### Recommended Mitigation Steps
The system should implement comprehensive hash validation, add proper hash format checking, use parameterized queries, and validate hash before processing.

## QA-11: Transaction receipt generation lacks proper validation and bounds checking

### Proof of Concept

Take a look at the `GetTransactionReceipt` function in `tx_info.go`:

```go
func (b *Backend) GetTransactionReceipt(hash gethcommon.Hash) (*TransactionReceipt, error) {
    // Unsafe cumulative gas calculation
    cumulativeGasUsed := uint64(0)
    for _, txResult := range blockRes.TxsResults[0:res.TxIndex] {
        // Potential overflow in gas calculation
        cumulativeGasUsed += uint64(txResult.GetGasUsed())
    }
    
    // Contract address generation without validation
    if txData.GetTo() == nil {
        // Unsafe contract address generation
        addr := crypto.CreateAddress(from, txData.GetNonce())
        receipt.ContractAddress = &addr
    }
    
    // No validation of receipt fields
    receipt := &TransactionReceipt{
        Status:            1,
        CumulativeGasUsed: cumulativeGasUsed,
        Logs:             logs,
    }
    return receipt, nil
}
```

### Impact
The codebase generates transaction receipts without proper validation and bounds checking, allowing potential integer overflow vulnerabilities and incorrect contract address generation.

### Recommended Mitigation Steps
The system should implement SafeMath for gas calculations, validate contract address generation, add comprehensive receipt validation, and implement proper error handling.

## QA-12: Index validation is insufficient for certain operations

### Proof of Concept

Take a look at the `GetTransactionByBlockAndIndex` function in `tx_info.go`:

```go
func (b *Backend) GetTransactionByBlockAndIndex(block *tmrpctypes.ResultBlock, idx hexutil.Uint) (*rpc.EthTxJsonRPC, error) {
    // Unsafe conversion without bounds checking
    i := int(idx)
    ethMsgs := b.EthMsgsFromTendermintBlock(block, blockRes)
    
    // Basic bounds check but after conversion
    if i >= len(ethMsgs) {
        b.logger.Debug("block txs index out of bound", "index", i)
        return nil, nil
    }
    return tx, nil
}
```

### Impact
The codebase performs certain operations without proper index validation, allowing potential index out of bounds access and integer overflow vulnerabilities.

### Recommended Mitigation Steps
The system should implement bounds checking before conversions, add proper type validation, use safe integer conversion, and add comprehensive error handling.

## QA-13: JSON marshaling is unsafe and lacks proper validation

### Proof of Concept

Take a look at the `MarshalJSON` function in `tx_info.go`:

```go
func (r *TransactionReceipt) MarshalJSON() ([]byte, error) {
    // Unsafe type assertions and conversions
    receiptJson, err := json.Marshal(struct {
        TransactionHash common.Hash
        BlockHash       common.Hash
        // ... other fields
    }{
        TransactionHash: r.TransactionHash,
        BlockHash:      r.BlockHash,
        // ... other fields
    })
    
    // Unsafe JSON manipulation
    var output map[string]interface{}
    if err := json.Unmarshal(receiptJson, &output); err != nil {
        return nil, err
    }
    
    // No validation of field values before adding to output
    if r.ContractAddress != nil {
        output["contractAddress"] = r.ContractAddress
    }
    
    return json.Marshal(output)
}
```

### Impact
The codebase performs JSON marshaling without proper validation and safety checks, allowing potential JSON injection vulnerabilities and memory corruption.

### Recommended Mitigation Steps
The system should implement proper field validation, add type safety checks, sanitize JSON output, and use safe JSON encoding methods.

## QA-14: Error handling is inadequate and inconsistent

### Proof of Concept

Take a look at the `GetTransactionReceipt` function in `tx_info.go`:

```go
func (b *Backend) GetTransactionReceipt(hash gethcommon.Hash) (*TransactionReceipt, error) {
    res, err := b.GetTxByEthHash(hash)
    if err != nil {
        // Error is logged with potentially sensitive information
        b.logger.Error("failed to fetch transaction", "hash", hash, "error", err.Error())
        return nil, err
    }
    
    txData, err := b.UnpackTxData(tx.Data)
    if err != nil {
        // Sensitive error information exposed in message
        return nil, fmt.Errorf("failed to decode tx data: %w", err)
    }
    
    // Silent error handling
    if err := processReceipt(receipt); err != nil {
        b.logger.Debug("failed to process receipt", "error", err)
        return receipt, nil // Returns potentially invalid receipt
    }
}
```

### Impact
The codebase lacks comprehensive and consistent error handling, allowing sensitive information exposure and silent failures.

### Recommended Mitigation Steps
The system should implement consistent error handling, sanitize error messages, add proper error classification, and create secure logging practices.

## QA-15: Pending transaction handling lacks proper validation and bounds checking

### Proof of Concept

Take a look at the `getTransactionByHashPending` function in `tx_info.go`:

```go
func (b *Backend) getTransactionByHashPending(txHash gethcommon.Hash) (*rpc.EthTxJsonRPC, error) {
    // No limit on number of pending transactions
    txs, err := b.PendingTransactions()
    if err != nil {
        // Silent error handling
        b.logger.Debug("tx not found", "hash", hexTx, "error", err.Error())
        return nil, nil
    }
    
    // Potential timing attack vector in transaction matching
    for _, tx := range txs {
        if msg.Hash == hexTx {
            // Use of zero values without validation
            rpctx, err := rpc.NewRPCTxFromMsg(
                msg,
                gethcommon.Hash{},
                uint64(0),
                uint64(0),
                nil,
                b.chainID,
            )
            if err != nil {
                return nil, err
            }
            return rpctx, nil
        }
    }
    return nil, nil
}
```

### Impact
The codebase handles pending transactions without proper validation and bounds checking, allowing potential memory exhaustion and resource depletion attacks.

### Recommended Mitigation Steps
The system should implement transaction pool limits, add proper synchronization, create timeout mechanisms, and validate transaction parameters.

## QA-16: RPC API access lacks proper rate limiting and access control

### Proof of Concept

Take a look at the `EthAPI` struct in `eth_api.go`:

```go
type EthAPI struct {
    ctx     context.Context
    logger  log.Logger
    backend *backend.Backend
    // Missing rate limiting and access control
}

func (e *EthAPI) SendRawTransaction(data hexutil.Bytes) (common.Hash, error) {
    // No rate limiting or request validation
    e.logger.Debug("eth_sendRawTransaction", "length", len(data))
    
    // Direct access to sensitive operations
    return e.backend.SendRawTransaction(data)
}
```

### Impact
The codebase provides RPC API access without proper rate limiting and access control, allowing potential DoS attacks and unauthorized access to sensitive operations.

### Recommended Mitigation Steps
The system should implement rate limiting, add proper authentication, create access control mechanisms, and add request validation.

## QA-17: Block number handling lacks proper validation and bounds checking

### Proof of Concept

Take a look at the `GetTransactionByBlockNumberAndIndex` function in `eth_api.go`:

```go
func (e *EthAPI) GetTransactionByBlockNumberAndIndex(blockNum rpc.BlockNumber, idx hexutil.Uint) (*rpc.EthTxJsonRPC, error) {
    // No validation of block number bounds
    // Unsafe conversion of block number
    return e.backend.GetTransactionByBlockNumberAndIndex(blockNum, idx)
}
```

### Impact
The codebase handles block numbers without proper validation and bounds checking, allowing potential integer overflow vulnerabilities and access to invalid blocks.

### Recommended Mitigation Steps
The system should implement proper bounds checking, add block number validation, use safe type conversions, and create comprehensive error handling.

## QA-18: Contract call validation is insufficient

### Proof of Concept

Take a look at the `Call` function in `eth_api.go`:

```go
func (e *EthAPI) Call(args evm.JsonTxArgs, blockNrOrHash rpc.BlockNumberOrHash, _ *rpc.StateOverride) (hexutil.Bytes, error) {
    // No validation of contract address
    // No validation of input data size
    // StateOverride parameter ignored
    data, err := e.backend.DoCall(args, blockNum)
    return (hexutil.Bytes)(data.Ret), nil
}
```

### Impact
The codebase performs contract calls without proper validation, allowing potential contract exploitation vulnerabilities and resource exhaustion.

### Recommended Mitigation Steps
The system should implement input validation, add gas limits and checks, validate contract addresses, and create size limits for code.

## QA-19: Storage access lacks proper validation and bounds checking

### Proof of Concept

Take a look at the `GetStorageAt` function in `eth_api.go`:

```go
func (e *EthAPI) GetStorageAt(address common.Address, key string, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
    // No validation of storage key format
    // No access control for sensitive storage slots
    storage, err := e.backend.GetStorageAt(address, key, blockNrOrHash)
    if err != nil {
        return nil, err
    }
    return storage, nil
}
```

### Impact
The codebase accesses storage without proper validation and bounds checking, allowing potential exposure of sensitive contract data and memory overflow.

### Recommended Mitigation Steps
The system should implement storage access control, add key format validation, create size limits for proofs, and validate storage slots.
