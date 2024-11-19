
# QA Nibiru

| Issue ID | Description |
| -------- | ----------- |
| [QA-01](#qa-01-antehandle-does-not-properly-account-for-the-base-fee-component-in-dynamic-fee-transactions) | `AnteHandle` does not properly account for the base fee component in dynamic fee transactions |
| [QA-02](#qa-02-antehandle-only-checks-transfer-value-without-considering-max-gas-fees) | `AnteHandle` only checks transfer value without considering max gas fees |
| [QA-03](#qa-03-missing-description-of-bloom-filter-event-emission) | Missing description of bloom filter event emission |
| [QA-04](#qa-04-tracecall-message-authentication-bypass) | `TraceCall` message authentication bypass |
| [QA-05](#qa-05-transient-bloom-filter-state-is-not-persisted-between-multiple-calcbloomfromlogs-calls) | Transient bloom filter state is not persisted between multiple `CalcBloomFromLogs` calls |
| [QA-06](#qa-06-old-way-of-passing-storekey) | Old way of passing `StoreKey` |
| [QA-07](#qa-07-unnecessary-event-emission-which-does-not-follow-the-docs) | Unnecessary event emission which does not follow the docs |
| [QA-08](#qa-08-missing-interface-compliance-check-for-accesslistaddaccountchange-type) | Missing interface compliance check for `accessListAddAccountChange` type |
| [QA-09](#qa-09-multiple-nil-pointer-dereference-could-cause-panic-in-settxdefaults-function-when-processing-tx-args) | Multiple nil pointer dereference could cause panic in `SetTxDefaults` function when processing tx args |
| [QA-10](#qa-10-gettransactionlogs-could-panic-due-to-unchecked-array-access-of-txsresults) | `GetTransactionLogs` could panic due to unchecked array access of `TxsResults` |
| [QA-11](#qa-11-retrieveevmtxfeesfromblock-could-cause-panic-in-the-percentile-calculation-loop) | `retrieveEVMTxFeesFromBlock` could cause panic in the percentile calculation loop |
| [QA-12](#qa-12-state-could-be-bloated-because-zero-value-storage-slots-still-persist-instead-of-being-deleted-during-statedb-commit) | State could be bloated because zero-value storage slots still persist instead of being deleted during `StateDB Commit` |
| [QA-13](#qa-13-getproof-uses-stale-height-0-for-latestpending-block-queries) | `GetProof` uses stale height (0) for latest/pending block queries |
| [QA-14](#qa-14-feehistory-block-retrieval-method-skips-error-validation) | `FeeHistory` block retrieval method skips error validation |
| [QA-15](#qa-15-parseweiasmultipleofmicronibi-doesnt-properly-follow-go-error-handling-convention) | `ParseWeiAsMultipleOfMicronibi` doesn't properly follow Go error handling convention |
| [QA-16](#qa-16-missing-chain-configuration-support-in-traceethtxmsgs-transaction-tracer) | Missing chain configuration support in `TraceEthTxMsg`'s transaction tracer |
| [QA-17](#qa-17-setcode-function-doesnt-delete-empty-contract-code-as-documented) | `SetCode` function doesn't delete empty contract code as documented |
| [QA-18](#qa-18-funtokenmapping-doesnt-validate-input-format-for-token-addressdenom-resolution) | `FunTokenMapping` doesn't validate input format for token address/denom resolution |
| [QA-19](#qa-19-foreachstorage-method-fails-to-completely-iterate-over-dirty-storage) | `ForEachStorage` method fails to completely iterate over dirty storage |
| [QA-20](#qa-20-typo) | Typo |
| [QA-21](#qa-21-gas-estimator-only-validates-vm-errors-at-gas-cap-missing-failed-txs-below-cap) | Gas estimator only validates vm errors at gas cap, missing failed txs below cap |
| [QA-22](#qa-22-getsender-errors) | `GetSender` errors |
| [QA-23](#qa-23-ethcall-overwrites-user-provided-nonce-values-and-limits-ability-to-simulate-transactions) | `EthCall` overwrites user-provided nonce values and limits ability to simulate transactions |
| [QA-24](#qa-24-add-extra-layer-of-chain-id-verification-in-evmante_sigverify-to-prevent-replay-attacks) | Add extra layer of chain ID verification in `evmante_sigverify` to prevent replay attacks |
| [QA-25](#qa-25-hexbyte-type-has-been-abandoned) | `HexByte` type has been abandoned |






## [QA-01] `AnteHandle` does not properly account for the base fee component in dynamic fee transactions

When validating a dynamic fee transaction (type 2 EIP-1559), it checks if [`baseFeeMicronibi`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_validate_basic.go#L118-L123) is nil and rejects the transaction if it is:

```go
if baseFeeMicronibi == nil && txData.TxType() == gethcore.DynamicFeeTxType {
    return ctx, errorsmod.Wrap(
        gethcore.ErrTxTypeNotSupported,
        "dynamic fee tx not supported",
    )
}
```

Albeit, the fn then proceeds to validate the transaction fee without considering the base fee for dynamic fee transactions. The fee validation is done [here](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_validate_basic.go#L125-L131):

```go
txFee = txFee.Add(
    sdk.Coin{
        Denom:  evm.EVMBankDenom,
        Amount: sdkmath.NewIntFromBigInt(txData.Fee()),
    },
)
```

The issue is that for dynamic fee transactions, the actual fee that will be charged should be:

```go
actual_fee = (base_fee + priority_fee_per_gas) * gas_limit
```

But the protocol is only using `txData.Fee()` which might not properly account for the base fee component in dynamic fee transactions. As a result, txs might be accepted with insufficient fees and also there could be cases where users could pay less than the required base fee.

### Recommendation
Properly calculate the total fee for dynamic fee transactions by considering both the base fee and priority fee.


## [QA-02] `AnteHandle` only checks transfer value without considering max gas fees


Take a look at the [`CanTransferDecorator.AnteHandle`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_can_transfer.go#L58-L64) function with focus on the gas fee validation logic

```go
if msgEthTx.EffectiveGasCapWei(baseFeeWeiPerGas).Cmp(baseFeeWeiPerGas) < 0 {
    return ctx, errors.Wrapf(
        sdkerrors.ErrInsufficientFee,
        "gas fee cap (wei) less than block base fee (wei); (%s < %s)",
        coreMsg.GasFeeCap(), baseFeeWeiPerGas,
    )
}
```

The problem is that this check happens AFTER the `AsMessage` call but BEFORE checking if the user has sufficient balance. This creates a case where::

1. The fn validates that the gas fee cap is sufficient
2. But it doesn't verify that the user has enough balance to cover both:
   - The transaction value (`coreMsg.Value()`)
   - AND the maximum gas fees they might need to pay

The current balance check [here](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_can_transfer.go#L83-L94) only verifies if the user has enough balance for the transfer value:

```go
if coreMsg.Value().Sign() > 0 &&
    !evmInstance.Context.CanTransfer(stateDB, coreMsg.From(), coreMsg.Value()) {
    balanceWei := stateDB.GetBalance(coreMsg.From())
    return ctx, errors.Wrapf(
        sdkerrors.ErrInsufficientFunds,
        "failed to transfer %s wei (balance=%s) from address %s using the EVM block context transfer function",
        coreMsg.Value(),
        balanceWei,
        coreMsg.From(),
    )
}
```

Scenario:
1. A user has enough balance to cover the transfer value
2. The gas fee cap is above the base fee
3. But the user doesn't have enough total balance to cover both the transfer AND the maximum possible gas fees


### Recommendation

 AnteHandle should verify that the user has enough balance to cover:
`transfer_value + (gas_limit * effective_gas_price)`

This is important because in Ethereum-compatible chains, users should have enough balance to cover both the transfer value and the maximum possible gas fees before the transaction is executed.






## [QA-03] Missing description of bloom filter event emission

The comment [here](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/hooks.go#L18) is misleading:

```go
// EndBlock also retrieves the bloom filter value from the transient store and commits it to the
```

The comment abruptly ends with "commits it to the" without specifying where the bloom filter is being committed to. In reality, the function only retrieves the bloom filter and emits it as an event - it doesn't actually commit it anywhere.








## [QA-04] `TraceCall` message authentication bypass

Unlike [`TraceTx`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L503), which properly uses a signer to create a message from a signed transaction, [`TraceCall`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L611-L615) creates a message directly from unsigned data.

```go
// req.Msg is not signed, so to gethcore.Message because it's not signed and will fail on getting
msgEthTx := req.Msg
txData, err := evm.UnpackTxData(req.Msg.Data)
if err != nil {
    return nil, grpcstatus.Errorf(grpccodes.Internal, "failed to unpack tx data: %s", err.Error())
}
```

This could cause problems because there's no validation of the sender address since the message isn't properly signed. Although this [comment](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L610) acknowledges the message isn't signed but doesn't fully address the implications. The function bypasses the normal transaction signing process that would occur in a real transaction

### Recommendation
Require signed messages for tracing and also add explicit validation of the sender address








## [QA-05] Transient bloom filter state is not persisted between multiple `CalcBloomFromLogs` calls

If we take a look at [`CalcBloomFromLogs`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/evm_state.go#L158-L167) function,

```go
func (state EvmState) CalcBloomFromLogs(
    ctx sdk.Context, newLogs []*gethcore.Log,
) (bloom gethcore.Bloom) {
    if len(newLogs) > 0 {
        bloomInt := state.GetBlockBloomTransient(ctx)
        bloomInt.Or(bloomInt, big.NewInt(0).SetBytes(gethcore.LogsBloom(newLogs)))
        bloom = gethcore.BytesToBloom(bloomInt.Bytes())
    }
    return bloom
}
```

it doesn't persist the updated bloom filter back to the state. After calculating the new bloom filter by combining the existing one with the new logs, it only returns the result but never calls `state.BlockBloom.Set()` to save the updated value.

The function gets the current bloom filter via `GetBlockBloomTransient`. It combines it with new logs using the `Or` operation. It converts the result to a `Bloom` type. But it never saves this new combined bloom filter back to the transient store

This means that if multiple calls to `CalcBloomFromLogs` happen within the same block, each call will only see the last persisted state rather than accumulating all logs' bloom filters correctly. This could lead to missing events when filtering logs later.

### Recommendation
Consider modifying the function to persist the updated bloom filter:

```diff
func (state EvmState) CalcBloomFromLogs(
    ctx sdk.Context, newLogs []*gethcore.Log,
) (bloom gethcore.Bloom) {
    if len(newLogs) > 0 {
        bloomInt := state.GetBlockBloomTransient(ctx)
        bloomInt.Or(bloomInt, big.NewInt(0).SetBytes(gethcore.LogsBloom(newLogs)))
        bloom = gethcore.BytesToBloom(bloomInt.Bytes())
+        state.BlockBloom.Set(ctx, bloom.Bytes())
    }
    return bloom
}
```








## [QA-06] Old way of passing `StoreKey`


Nibiru still uses old way of passing store to keeper as seen in the [`NewKeeper` function](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/keeper.go#L76):

```go
61: func NewKeeper(
75: 		cdc:           cdc,
76: 		storeKey:      storeKey,
77: 		transientKey:  transientKey,
78: 		authority:     authority,
79: 		EvmState:      NewEvmState(cdc, storeKey, transientKey),
80: 		FunTokens:     NewFunTokenState(cdc, storeKey),
81: 		accountKeeper: accKeeper,
82: 		Bank:          bankKeeper,
83: 		stakingKeeper: stakingKeeper,
84: 		tracer:        tracer,
85: 	}
86: }
```

Although this is not a problem for Nibiru, it is against the design decisions that Cosmos SDK took, according to the [docs](https://github.com/cosmos/cosmos-sdk/blob/main/UPGRADING.md#module-wiring).

>The following modules NewKeeper function now take a KVStoreService instead of a StoreKey









## [QA-07] Unnecessary event emission which does not follow the docs


Referencing the [docs here,](https://github.com/cosmos/cosmos-sdk/blob/main/UPGRADING.md#all-2)

>EventTypeMessage events, with sdk.AttributeKeyModule and sdk.AttributeKeySender are now emitted directly at message execution (in baseapp). This means that the following boilerplate should be removed from all your custom modules:
>
>ctx.EventManager().EmitEvent( sdk.NewEvent( sdk.EventTypeMessage, sdk.NewAttribute(sdk.AttributeKeyModule, types.AttributeValueCategory), sdk.NewAttribute(sdk.AttributeKeySender, signer/sender), ), )

Albeit, `Nibiru` still makes use of as seen [here](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/msg_server.go#L655-L661):

```go
655: 	ctx.EventManager().EmitEvent(
656: 		sdk.NewEvent(
657: 			sdk.EventTypeMessage,
658: 			sdk.NewAttribute(sdk.AttributeKeyModule, evm.ModuleName),
659: 			sdk.NewAttribute(sdk.AttributeKeySender, msg.From().Hex()),
660: 			sdk.NewAttribute(evm.MessageEventAttrTxType, fmt.Sprintf("%d", txType)),
661: 		),
```









## [QA-08] Missing interface compliance check for `accessListAddAccountChange` type

Although there's a comment explaining the relationship between `accessListAddAccountChange` and `accessListAddSlotChange`, there's a missing type assertion line.

https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/statedb/journal.go#L280-L294


```go
type accessListAddAccountChange struct {
    address *common.Address
}

// When an (address, slot) combination is added, it always results in two
// journal entries if the address is not already present:
//  1. `accessListAddAccountChange`: a journal change for the address
//  2. `accessListAddSlotChange`: a journal change for the (address, slot)
//     combination.
//
// Thus, when reverting, we can safely delete the address, as no storage slots
// remain once the address entry is reverted.
func (ch accessListAddAccountChange) Revert(s *StateDB) {
    s.accessList.DeleteAddress(*ch.address)
}
```

Issue here is that there's no `var _ JournalChange = accessListAddAccountChange{}` line to ensure that `accessListAddAccountChange` properly implements the `JournalChange` interface. This type assertion is present for all other journal change types in the file (like [`createObjectChange`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/statedb/journal.go#L105), [`resetObjectChange`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/statedb/journal.go#L125), [`suicideChange`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/statedb/journal.go#L144), etc.) but is missing here.

It means the compiler won't catch if `accessListAddAccountChange` accidentally fails to implement the full `JournalChange` interface. If `JournalChange` interface is modified in the future by the protocol, they might miss updating this particular implementation

### Recommendation
```diff
type accessListAddAccountChange struct {
    address *common.Address
}

// When an (address, slot) combination is added, it always results in two
// journal entries if the address is not already present:
//  1. `accessListAddAccountChange`: a journal change for the address
//  2. `accessListAddSlotChange`: a journal change for the (address, slot)
//     combination.
//
// Thus, when reverting, we can safely delete the address, as no storage slots
// remain once the address entry is reverted.

+ var _ JournalChange = accessListAddAccountChange{}

func (ch accessListAddAccountChange) Revert(s *StateDB) {
    s.accessList.DeleteAddress(*ch.address)
}
```








## [QA-09] Multiple nil pointer dereference could cause panic in `SetTxDefaults` function when processing tx args

In the [`SetTxDefaults`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/rpc/backend/call_tx.go#L88-L212) function, there are several instances where pointer values are dereferenced without proper nil checks. The most notable one is in the gas estimation logic:

```go
if args.Gas == nil {
    // ... gas estimation logic ...
    args.Gas = &estimated
    b.logger.Debug("estimate gas usage automatically", "gas", args.Gas)
}
```

Although, there is a nil check for `args.Gas`, the function uses other pointer fields without proper nil checks:

1. When checking [`MaxFeePerGas` and `MaxPriorityFeePerGas`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/rpc/backend/call_tx.go#L119-L120):
```go
if args.MaxFeePerGas.ToInt().Cmp(args.MaxPriorityFeePerGas.ToInt()) < 0 {
    return args, fmt.Errorf("maxFeePerGas (%v) < maxPriorityFeePerGas (%v)", args.MaxFeePerGas, args.MaxPriorityFeePerGas)
}
```

2. When using [`Data` and `Input`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/rpc/backend/call_tx.go#L158-L159):
```go
if args.Data != nil && args.Input != nil && !bytes.Equal(*args.Data, *args.Input) {
    return args, errors.New("both 'data' and 'input' are set and not equal. Please use 'input' to pass transaction call data")
}
```

A malformed transaction with nil pointer fields could cause the application to panic. In turn, this could cause a DOS.

### Recommendation

Add proper nil checks before dereferencing pointer values.







## [QA-10]  `GetTransactionLogs` could panic due to unchecked array access of `TxsResults`

Take a look at how tx logs from events are parsed:

Here's the problematic section:

```go
func (e *EthAPI) GetTransactionLogs(txHash common.Hash) ([]*gethcore.Log, error) {
	e.logger.Debug("eth_getTransactionLogs", "hash", txHash)

	hexTx := txHash.Hex()
	res, err := e.backend.GetTxByEthHash(txHash)
	if err != nil {
		e.logger.Debug("tx not found", "hash", hexTx, "error", err.Error())
		return nil, nil
	}

	if res.Failed {
		// failed, return empty logs
		return nil, nil
	}

	resBlockResult, err := e.backend.TendermintBlockResultByNumber(&res.Height)
	if err != nil {
		e.logger.Debug("block result not found", "number", res.Height, "error", err.Error())
		return nil, nil
	}

@>	// parse tx logs from events
@>	index := int(res.MsgIndex) // #nosec G701
@>	return backend.TxLogsFromEvents(resBlockResult.TxsResults[res.TxIndex].Events, index)
}

```

Issue here's that theres no bounds checking before accessing `TxsResults[res.TxIndex]`. If `res.TxIndex` is out of bounds of the `TxsResults` slice, this will cause a panic. This is dangerous because the values come from external input (transaction lookup).


### Recommendation
Consider adding bounds checking before accessing the slice:

```diff
func (e *EthAPI) GetTransactionLogs(txHash common.Hash) ([]*gethcore.Log, error) {
    e.logger.Debug("eth_getTransactionLogs", "hash", txHash)

  ...snip...

    resBlockResult, err := e.backend.TendermintBlockResultByNumber(&res.Height)
    if err != nil {
        e.logger.Debug("block result not found", "number", res.Height, "error", err.Error())
        return nil, nil
    }

+    // Add bounds checking
+    if int(res.TxIndex) >= len(resBlockResult.TxsResults) {
+        e.logger.Debug("tx index out of bounds", "tx_index", res.TxIndex, "length", len(resBlockResult.TxsResults))
+        return nil, fmt.Errorf("transaction index out of bounds")
+    }

    // parse tx logs from events
    index := int(res.MsgIndex)
    return backend.TxLogsFromEvents(resBlockResult.TxsResults[res.TxIndex].Events, index)
}
```








## [QA-11] `retrieveEVMTxFeesFromBlock` could cause panic in the percentile calculation loop

Take a look at the [`retrieveEVMTxFeesFromBlock`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/rpc/backend/utils.go#L198-L211) function

```go
var txIndex int
sumGasUsed := sorter[0].gasUsed

for i, p := range rewardPercentiles {
    thresholdGasUsed := uint64(blockGasUsed * p / 100) // #nosec G701
    for sumGasUsed < thresholdGasUsed && txIndex < ethTxCount-1 {
        txIndex++
        sumGasUsed += sorter[txIndex].gasUsed
    }
    targetOneFeeHistory.Reward[i] = sorter[txIndex].reward
}
```

It doesn't handle the case where `sorter` is empty (i.e., `ethTxCount == 0`) properly. While there is a check [here](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/rpc/backend/utils.go#L192):

```go
if ethTxCount == 0 {
    return nil
}
```

it immediately after this check tries to access `sorter[0]` without any additional validation:

```go
sumGasUsed := sorter[0].gasUsed
```

This could lead to a panic if `sorter` is empty, despite the previous check. The issue is that the function returns `nil` when there are no transactions, but it should probably initialize the rewards array with zero values to maintain consistency with the expected return format.








## [QA-12]  State could be bloated because zero-value storage slots still persist instead of being deleted during `StateDB Commit`

Take a look at this part of [commitCtx](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/statedb/statedb.go#L557-L565) function:

```go
for _, key := range obj.DirtyStorage.SortedKeys() {
    dirtyVal := obj.DirtyStorage[key]
    // Values that match origin storage are not dirty.
    if dirtyVal == obj.OriginStorage[key] {
        continue
    }
    // Persist committed changes
    s.keeper.SetState(ctx, obj.Address(), key, dirtyVal.Bytes())
    obj.OriginStorage[key] = dirtyVal
}
```




When a storage slot is set to zero (which is equivalent to deletion in Ethereum), the code only checks if the dirty value equals the origin value but doesn't explicitly handle zero values.

Typically, in Ethereum's state model, when a storage slot is set to zero, it should be deleted from the state trie. Albeit, `commitCtx` only updates the value without properly removing zero values.

As a result, protocol could end up with unnecessary storage bloat because zero values remain stored. Also higher gas costs for future operations since the slot still exists

### Recommendation
Explicitly check for zero values and remove them from state storage






## [QA-13] `GetProof` uses stale height (0) for latest/pending block queries


In the [`GetProof` function](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/rpc/backend/account_info.go#L50-L79), especially the timing issue with context creation and height adjustment:


```go
// if the height is equal to zero, meaning the query condition of the block
// is either "pending" or "latest"
if height == 0 {
    bn, err := b.BlockNumber()
    if err != nil {
        return nil, err
    }

    if bn > math.MaxInt64 {
        return nil, fmt.Errorf("not able to query block number greater than MaxInt64")
    }

    height = int64(bn) //#nosec G701 -- checked for int overflow already 
}
```

Issue here is that the function creates a new context with `height=0`
```go
ctx := rpc.NewContextWithHeight(height)
```
But then updates the height value afterwards. This means that the `ctx` used in the `EthAccount` query might be using the wrong height:

```go
res, err := b.queryClient.EthAccount(ctx, req)
```

The `ctx` is created with the initial height (which could be `0`) before the height adjustment logic is performed. This means that even if the height is adjusted later, the query is still using the original context with `height=0`.

As a result, we have inconsistent state queries as queries could be returning data from wrong block heights.

### Recommendation
The context creation should happen after the height adjustment logic:

```diff
_, err = b.TendermintBlockByNumber(blockNum)
	if err != nil {
		// the error message imitates geth behavior
		return nil, errors.New("header not found")
	}
-	ctx := rpc.NewContextWithHeight(height)

	// if the height is equal to zero, meaning the query condition of the block
	// is either "pending" or "latest"
	if height == 0 {
		bn, err := b.BlockNumber()
		if err != nil {
			return nil, err
		}

		if bn > math.MaxInt64 {
			return nil, fmt.Errorf("not able to query block number greater than MaxInt64")
		}

+	ctx := rpc.NewContextWithHeight(height)
		height = int64(bn) //#nosec G701 -- checked for int overflow already
	}

	clientCtx := b.clientCtx.WithHeight(height)
```







## [QA-14] `FeeHistory` block retrieval method skips error validation

There are 2 instances in the [`FeeHistory`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/rpc/backend/chain_info.go#L125-L135) method where the function only checks if the returned block is nil but doesn't check the error value (err). 

```go
// tendermint block
		tendermintblock, err := b.TendermintBlockByNumber(rpc.BlockNumber(blockID))
		if tendermintblock == nil {
			return nil, err
		}
```


and

```go
// eth block
		ethBlock, err := b.GetBlockByNumber(rpc.BlockNumber(blockID), true)
		if ethBlock == nil {
			return nil, err
		}
```

If there's an error but the block isn't nil, the error will be ignored. Also, if there's no error but the block is nil, it'll return a nil error, which doesn't properly indicate why the block wasn't found


### Recommendation
Consider checking the errors first








## [QA-15] `ParseWeiAsMultipleOfMicronibi` doesn't properly follow Go error handling convention

Taking a look at the [`ParseWeiAsMultipleOfMicronibi`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/msg_server.go#L406-L411) function:

```go
// err if weiInt is too small
tenPow12 := new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil)
if weiInt.Cmp(tenPow12) < 0 {
    return weiInt, fmt.Errorf(
        "wei amount is too small (%s), cannot transfer less than 1 micronibi. 1 NIBI == 10^6 micronibi == 10^18 wei", weiInt)
}
```

The problem is that the function is checking if the wei amount is less than 10^12, but according to the error message and the comment, the intended relationship is:
- 1 NIBI = 10^6 micronibi
- 1 NIBI = 10^18 wei
- Therefore, 1 micronibi = 10^12 wei

The logic error is that when the wei amount is less than 10^12, the function returns the original wei amount along with an error message. This is inconsistent behavior because:

1. Returning both the original value AND an error violates the common Go pattern where you should return either a valid value OR an error, not both.
2. The caller might not check the error and use the returned wei amount, which was deemed too small and invalid.


### Recommendation
`ParseWeiAsMultipleOfMicronibi` should be modified to return `nil` as the value when returning an error:

```diff
// err if weiInt is too small
tenPow12 := new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil)
if weiInt.Cmp(tenPow12) < 0 {
-    return weiInt, fmt.Errorf(
+    return nil, fmt.Errorf(
        "wei amount is too small (%s), cannot transfer less than 1 micronibi. 1 NIBI == 10^6 micronibi == 10^18 wei", weiInt)
}
```






## [QA-16] Missing chain configuration support in `TraceEthTxMsg`'s transaction tracer


In the [`TraceEthTxMsg`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L743-L748) function,

```go
var (
    tracer    tracers.Tracer
    overrides *gethparams.ChainConfig  // @audit declared but never initialized
    err       error
    timeout   = DefaultGethTraceTimeout
)
```

The `overrides` variable is declared but never initialized, and it's then passed to the `logConfig` struct:

```go
logConfig := logger.Config{
    EnableMemory:     traceConfig.EnableMemory,
    DisableStorage:   traceConfig.DisableStorage,
    DisableStack:     traceConfig.DisableStack,
    EnableReturnData: traceConfig.EnableReturnData,
    Debug:            traceConfig.Debug,
    Limit:            int(traceConfig.Limit),
    Overrides:        overrides,  // @audit passing nil overrides
}
```

This is a problem because the `overrides` parameter is meant to allow customization of the chain configuration for tracing purposes, but since it's always nil, any chain-specific tracing configurations won't be applied. If the trace configuration from the request (`traceConfig`) includes chain configuration overrides, they are being ignored.

If there's a need to support custom chain configurations during tracing, the current implementation would not support that.

### Recommendation

Either initialize `overrides` with the chain configuration from `traceConfig` if provided or remove the `overrides` variable if chain configuration overrides are not needed






## [QA-17] `SetCode` function doesn't delete empty contract code as documented

Take a look at the [`SetCode`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/statedb.go#L148-L153) function 


```go
// SetCode: Setter for smart contract bytecode. Delete if code is empty.
// Implements the `statedb.Keeper` interface.
// Only called by `StateDB.Commit()`.
func (k *Keeper) SetCode(ctx sdk.Context, codeHash, code []byte) {
	k.EvmState.SetAccCode(ctx, codeHash, code)
}
```

it doesn't handle the case where code is empty (nil or zero length). According to the function's [comment](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/statedb.go#L148), it should "Delete if code is empty", but this isn't implemented. This could lead to storing empty code in the state, which wastes storage space and could cause confusion when querying contract code.


### Recommendation
`SetCode`should check if the code is empty and handle that case differently.







## [QA-18] `FunTokenMapping` doesn't validate input format for token address/denom resolution

Take a look at this part of the `grpc_query.go` contract especially in how [`FunTokenMapping`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L819-L844) handles token lookups:

```go
func (k Keeper) FunTokenMapping(
    goCtx context.Context, req *evm.QueryFunTokenMappingRequest,
) (*evm.QueryFunTokenMappingResponse, error) {
    ctx := sdk.UnwrapSDKContext(goCtx)

    // first try lookup by cosmos denom
    bankDenomIter := k.FunTokens.Indexes.BankDenom.ExactMatch(ctx, req.Token)
    funTokenMappings := k.FunTokens.Collect(ctx, bankDenomIter)
    if len(funTokenMappings) > 0 {
        // assumes that there is only one mapping for a given denom
        return &evm.QueryFunTokenMappingResponse{
            FunToken: &funTokenMappings[0],
        }, nil
    }

    erc20AddrIter := k.FunTokens.Indexes.ERC20Addr.ExactMatch(ctx, gethcommon.HexToAddress(req.Token))
    funTokenMappings = k.FunTokens.Collect(ctx, erc20AddrIter)
    if len(funTokenMappings) > 0 {
        // assumes that there is only one mapping for a given erc20 address
        return &evm.QueryFunTokenMappingResponse{
            FunToken: &funTokenMappings[0],
        }, nil
    }

    return nil, grpcstatus.Errorf(grpccodes.NotFound, "token mapping not found for %s", req.Token)
}
```

The function doesn't validate the input `req.Token` before using it. This is an issue because the token is used in two different contexts:
   - As a cosmos denom (which should follow denom validation rules)
   - As an Ethereum address (which should be a valid hex address)

Then it tries to interpret the input as both a bank denom and an ERC20 address without any clear indication to the caller about which format is expected. But if we look at [`funtoken.go`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/precompile/funtoken.go#L343-L345), specifically the `balance` method, we can see that it expects a valid Ethereum address for the token lookup:

```go
resp, e := p.evmKeeper.FunTokenMapping(ctx, &evm.QueryFunTokenMappingRequest{
    Token: funtokenErc20.Hex(),
})
```

### Recommendation
Consider adding proper input validation.








## [QA-19] `ForEachStorage` method fails to completely iterate over dirty storage

Take a look at [ForEachStorage method:](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/statedb/statedb.go#L318-L333)

```go
func (s *StateDB) ForEachStorage(addr common.Address, cb func(key, value common.Hash) bool) error {
    so := s.getStateObject(addr)
    if so == nil {
        return nil
    }
    s.keeper.ForEachStorage(s.evmTxCtx, addr, func(key, value common.Hash) bool {
        if value, dirty := so.DirtyStorage[key]; dirty {
            return cb(key, value)
        }
        if len(value) > 0 {
            return cb(key, value)
        }
        return true
    })
    return nil
}
```

The problem here is in how dirty storage values are treated. The method is supposed to iterate over all storage values but it has two issues:

It only checks dirty storage values when it finds a matching key in the keeper's storage, but it should also iterate through all dirty storage values independently. This means some dirty storage values might be missed if they don't exist in the keeper's storage yet.

Also, when a dirty value is found (`if value, dirty := so.DirtyStorage[key]; dirty`), the callback's return value is immediately returned from the inner function, which could prematurely end the iteration through the remaining storage slots.

Meaning if a contract has modified storage values (dirty storage) but these keys don't exist in the keeper's storage yet, these values won't be included in the iteration. Also, the iteration might stop early if a dirty value is encountered, potentially missing other storage slots.

### Recommendation

First iterate through all dirty storage values, then iterate through the keeper's storage values, skipping keys that were already processed from dirty storage







## [QA-20] Typo

Correct the typo on [this line](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L457) from `estimgate` to `estimate`

```go
475:   return nil, fmt.Errorf("Estimgate gas VMError: %s", result.VmError)
```



## [QA-21] Gas estimator only validates vm errors at gas cap, missing failed txs below cap

Take a look at the [binary search](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L440-L459) implementation:

```go
// The gas limit is now the highest gas limit that results in an executable transaction
// Reject the transaction as invalid if it still fails at the highest allowance
if hi == gasCap {
    failed, result, err := executable(hi)
    if err != nil {
        return nil, fmt.Errorf("eth call exec error: %w", err)
    }

    if failed && result != nil {
        if result.VmError == vm.ErrExecutionReverted.Error() {
            return nil, fmt.Errorf("Estimate gas VMError: %w", evm.NewRevertError(result.Ret))
        }

        if result.VmError == vm.ErrOutOfGas.Error() {
            return nil, fmt.Errorf("gas required exceeds allowance (%d)", gasCap)
        }

        return nil, fmt.Errorf("Estimgate gas VMError: %s", result.VmError)
    }
}
```

Problem heres that the fn only checks for execution failures when `hi == gasCap`, but doesn't check for failures in other cases. This means that if the binary search finds a gas value that technically executes but results in a revert or other VM error (at a value less than gasCap), the function will return that gas value as successful when it should actually return an error.

### Recommendation
Consider checking for vm errors and execution failures for any gas value that the binary search settles on, not just when `hi == gasCap` & also handle the case where `result` is nil but `failed` is true






## [QA-22] `GetSender` errors

If [`ethMsg.GetSender(b.chainID)`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/rpc/backend/utils.go#L94) returns an error, the function continues to the next message. This is generally fine, but it might be worth logging the error for debugging purposes.





## [QA-23] `EthCall` overwrites user-provided nonce values and limits ability to simulate transactions

Take a look at the [`EthCall` function](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L276-L282):

```go
// ApplyMessageWithConfig expect correct nonce set in msg
nonce := k.GetAccNonce(ctx, args.GetFrom())
args.Nonce = (*hexutil.Uint64)(&nonce)

msg, err := args.ToMessage(req.GasCap, cfg.BaseFeeWei)
if err != nil {
    return nil, grpcstatus.Error(grpccodes.InvalidArgument, err.Error())
}
```

The function overwrites any user-provided nonce with the current account nonce from state. This limits the behavior for `eth_call` because the [`eth_call RPC Method`](https://www.quicknode.com/docs/ethereum/eth_call) executes a new message call immediately without creating a transaction on the block chain, thus it makes sense for `eth_call` to respect the user-provided nonce if one is specified, as it should allow users to simulate transactions at different nonce values.

By forcibly setting the nonce to the current account nonce, it prevents users from simulating transactions that might depend on a specific nonce value which could be important for testing contract interactions that depend on nonce logic.

### Recommendation
Consider only setting the nonce if one wasn't provided in the original request

```diff
+ if args.Nonce == nil {
      nonce := k.GetAccNonce(ctx, args.GetFrom())
      args.Nonce = (*hexutil.Uint64)(&nonce)
}
```





## [QA-24] Add extra layer of chain ID verification in `evmante_sigverify` to prevent replay attacks


Take a look at `AnteHandle` function:

https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_sigverify.go#L36-L39

```go
36: 	chainID := esvd.evmKeeper.EthChainID(ctx)
37: 	ethCfg := evm.EthereumConfig(chainID)
38: 	blockNum := big.NewInt(ctx.BlockHeight())
39: 	signer := gethcore.MakeSigner(ethCfg, blockNum)

```

While the function retrieves the chain ID and creates a signer using it, it doesnt actually verify that the transaction's chain ID matches the expected chain ID of the network. 

Even though it checks for protected transactions (`ethTx.Protected()`), it doesn't explicitly verify that the transaction's chain ID matches the expected chain ID. A transaction could potentially be valid on Arbitrum and then replayed on BSC because this check is missing.

This could allow replay attacks across different networks that use the same address scheme.


### Recommendation
Consider explicitly adding chain ID verification after retrieving the sender. A check like this

```diff
// After the sender verification
+  txChainID := ethTx.ChainId()
+  if txChainID.Cmp(chainID) != 0 {
+       return ctx, errors.Wrapf(
+           sdkerrors.ErrUnauthorized,
+           "invalid chain ID; got %d, expected %d", txChainID, chainID,
+       )
+  }
```





## [QA-25] `HexByte` type has been abandoned

With the release of v0.50.x, the Cosmos SDK [dropped its use of the bytes.HexBytes type](https://github.com/cosmos/cosmos-sdk/blob/release/v0.50.x/UPGRADING.md#migration-to-cometbft-part-2) in favor of the `[]byte type`. Consider adapting [x/evm/keeper/msg_server.go](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/msg_server.go#L641) accordingly.

```go
641: 		eventEthereumTx.Hash = tmbytes.HexBytes(tmtypes.Tx(ctx.TxBytes()).Hash()).String()
```

