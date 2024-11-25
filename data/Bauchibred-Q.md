# QA Report for **Nibiru**

## Table of Contents

| Issue ID                                                                                                                         | Description                                                                                                      |
| -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| [QA-01](#qa-01-some-tokens-would-be-bricked-when-integrated-with-erc20.go)                                                       | Some tokens would be bricked when integrated with `erc20.go`                                                     |
| [QA-02](#qa-02-usage-of-heavy-block-result-types-in-json-rpc-service-slows-down-the-api-and-degrades-performance/response-times) | Usage of heavy block result types in JSON-RPC service slows down the API and degrades performance/response times |
| [QA-03](#qa-03-unsanitized-error-messages-in-grpc-api-responses-should-be-frowned-upon)                                          | Unsanitized error messages in gRPC API responses should be frowned upon                                          |
| [QA-04](#qa-04-gas-configuration-currently-overcharges-users-since-it-takes-into-account-additional-gas-costs)                   | Gas configuration currently overcharges users since it takes into account additional gas costs                   |
| [QA-05](#qa-05-journal-cant-be-easily-reset)                                                                                     | Journal can't be easily reset                                                                                    |
| [QA-06](#qa-06-dosing-by-spamming-transactions-is-allowed)                                                                       | DOSing by spamming transactions is allowed                                                                       |
| [QA-07](#qa-07-some-lower-decimal-tokens-cannot-be-transferred-in-nibiru)                                                        | Some lower decimal tokens cannot be transferred in Nibiru                                                        |
| [QA-08](<#qa-08-fix-typos-(multiple-instances)>)                                                                                 | Fix typos (Multiple instances)                                                                                   |
| [QA-09](#qa-09-mkr-and-its-like-of-tokens-that-return-bytes32-would-be-broken-when-integrated)                                   | MKR and its like of tokens that return `bytes32` would be broken when integrated                                 |
| [QA-10](#qa-10-getting-the-code-still-leads-to-a-panic-that-could-crash-the-node)                                                | Getting the code still leads to a panic that could crash the node                                                |
| [QA-11](#qa-11-missing-checktx-optimization-in-account-verification-leads-to-redundant-processing)                               | Missing CheckTx optimization in account verification leads to redundant processing                               |
| [QA-12](#qa-12-funtoken-currently-hardens-off-chain-tracking)                                                                    | FunToken currently hardens off-chain tracking                                                                    |
| [QA-13](<#qa-13-make-evmante_sigverify#antehandle()-more-efficient>)                                                             | Make `evmante_sigverify#AnteHandle()` more efficient                                                             |

## QA-01 Some tokens would be bricked when integrated with `erc20.go`

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/erc20.go#L124-L132

```go
// BalanceOf retrieves the balance of an ERC20 token for a specific account.
// Implements "ERC20.balanceOf".
func (e erc20Calls) BalanceOf(
	contract, account gethcommon.Address,
	ctx sdk.Context,
) (out *big.Int, err error) {
	return e.LoadERC20BigInt(ctx, e.ABI, contract, "balanceOf", account)
}

```

This function is used in multiple instances across scope where there is a need to query the balance of a contract for that specific token.

Now from the readme for the protocol, we conclude that protocol supports multiple tokens, issue however is that some tokens do not support for example the external call to query the `balanceof()`

I.e the call is made to the "balanceOf" method via [call_contract](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/call_contract.go#L32-L150) this however would then fail for tokens like Aura's stash tokens which do not implement the `balanceOf()` functionality.

> NB: Similarly this bug case is applicable to other ERC20funtionalities like `decimals()`, `name()` and `symbol()` etc that are not enforced in the [spec](https://eips.ethereum.org/EIPS/eip-20).

### Impact

DOS to most of the erc_20 logic for these tokens if they get supported, considering during transfers and some other transactions we expect to call the balance of to get the amount of tokens the user has in their account.

Considering the functionality is being directly queried here:

https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/precompile/funtoken.go#L265-L310

```go
func (p precompileFunToken) balance(
	start OnRunStartResult,
	contract *vm.Contract,
) (bz []byte, err error) {
	method, args, ctx := start.Method, start.Args, start.CacheCtx
	defer func() {
		if err != nil {
			err = ErrMethodCalled(method, err)
		}
	}()
	if err := assertContractQuery(contract); err != nil {
		return bz, err
	}

	addrEth, addrBech32, funtoken, err := p.parseArgsBalance(args, ctx)
	if err != nil {
		err = ErrInvalidArgs(err)
		return
	}

	erc20Bal, err := p.evmKeeper.ERC20().BalanceOf(funtoken.Erc20Addr.Address, addrEth, ctx)
	if err != nil {
		return
	}
	bankBal := p.evmKeeper.Bank.GetBalance(ctx, addrBech32, funtoken.BankDenom).Amount.BigInt()

	return method.Outputs.Pack([]any{
		erc20Bal,
		bankBal,
		struct {
			Erc20     gethcommon.Address `json:"erc20"`
			BankDenom string             `json:"bankDenom"`
		}{
			Erc20:     funtoken.Erc20Addr.Address,
			BankDenom: funtoken.BankDenom,
		},
		struct {
			EthAddr    gethcommon.Address `json:"ethAddr"`
			Bech32Addr string             `json:"bech32Addr"`
		}{
			EthAddr:    addrEth,
			Bech32Addr: addrBech32.String(),
		},
	}...)
}

```

### Recommended Mitigation Steps

Consider implementing a method to query the "balanceOf" method on a low level.

### Impact

### Recommended Mitigation Steps

## QA-02 Usage of heavy block result types in JSON-RPC service slows down the API and degrades performance/response times

### Proof of Concept

The JSON-RPC service makes excessive use of heavy block result types that require separate RPC requests and transfer full block data unnecessarily. This pattern is seen across multiple critical paths:

1. Block queries in [eth/rpc/backend/blocks.go](https://github.com/NibiruChain/nibiru/blob/main/eth/rpc/backend/blocks.go):

```go
func (b *Backend) TendermintBlockResultByNumber(height *int64) (*tmrpctypes.ResultBlockResults, error) {
    return sc.BlockResults(b.ctx, height)
}
```

2. Transaction processing with full block data:

```go
func (b *Backend) EthMsgsFromTendermintBlock(
    resBlock *tmrpctypes.ResultBlock,
    blockRes *tmrpctypes.ResultBlockResults,
) []*evm.MsgEthereumTx {
    txResults := blockRes.TxsResults
    // Processes entire block data even for single tx lookup
}
```

Each BlockResults call transfers complete block data including all transaction results, even when only specific fields are needed. This creates unnecessary overhead in:

- Memory usage from large response objects
- Network bandwidth from full data transfer
- Processing time for data transformation

### Impact

QA, considering this just causes a higher overhead and all, however to pinpoint some cases, this causes:

- Degraded API performance and response times
- Reduced system scalability under load
- Inefficient resource utilization

### Recommended Mitigation Steps

Consider replacing heavy types with lighter alternatives.

## QA-03 Unsanitized error messages in gRPC API responses should be frowned upon

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L255-L293

```go
func (k *Keeper) EthCall(
	goCtx context.Context, req *evm.EthCallRequest,
) (*evm.MsgEthereumTxResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	var args evm.JsonTxArgs
	err := json.Unmarshal(req.Args, &args)
	if err != nil {
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, err.Error())
	}
	chainID := k.EthChainID(ctx)
	cfg, err := k.GetEVMConfig(ctx, ParseProposerAddr(ctx, req.ProposerAddress), chainID)
	if err != nil {
		return nil, grpcstatus.Error(grpccodes.Internal, err.Error())
	}

	// ApplyMessageWithConfig expect correct nonce set in msg
	nonce := k.GetAccNonce(ctx, args.GetFrom())
	args.Nonce = (*hexutil.Uint64)(&nonce)

	msg, err := args.ToMessage(req.GasCap, cfg.BaseFeeWei)
	if err != nil {
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, err.Error())
	}

	txConfig := statedb.NewEmptyTxConfig(gethcommon.BytesToHash(ctx.HeaderHash()))

	// pass false to not commit StateDB
	res, _, err := k.ApplyEvmMsg(ctx, msg, nil, false, cfg, txConfig, false)
	if err != nil {
		return nil, grpcstatus.Error(grpccodes.Internal, err.Error())
	}

	return res, nil
}
```

The gRPC API endpoints directly return raw error messages to users without any sanitization or standardization.

### Impact

Information Disclosure: Raw error messages may contain internal implementation details that could help attackers formulate attack vectors, this is beacause the error messages are inconsistent across different endpoints.

### Recommended Mitigation Steps

Implement a centralized error handling system:

```go

// Define standard error types
var (
    ErrInvalidRequest = grpcstatus.Error(grpccodes.InvalidArgument, "invalid request parameters")
    ErrInternalError  = grpcstatus.Error(grpccodes.Internal, "internal server error")
    ErrNotFound      = grpcstatus.Error(grpccodes.NotFound, "resource not found")
)

// Create an error handler
func handleError(err error) error {
    switch {
    case errors.Is(err, ErrInvalidInput):
        return ErrInvalidRequest
    case errors.Is(err, ErrInternal):
        return ErrInternalError
    default:
        // Log the actual error for debugging but return a generic message
        logger.Error("internal error", "error", err)
        return ErrInternalError
    }
}
```

Update all gRPC handlers to use the centralized error handling:

```go
func (k *Keeper) EthCall(goCtx context.Context, req *evm.EthCallRequest) (*evm.MsgEthereumTxResponse, error) {
    if err := req.Validate(); err != nil {
        return nil, handleError(err)
    }
    // ...
}
```

## QA-04 Gas configuration currently overcharges users since it takes into account additional gas costs

### Proof of Concept

Take a look at [AnteDecEthGasConsume.AnteHandle](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_gas_consume.go#L158-L164):

```go
// FIXME: use a custom gas configuration that doesn't add any additional gas and only
// takes into account the gas consumed at the end of the EVM transaction.
newCtx := ctx.
    WithGasMeter(eth.NewInfiniteGasMeterWithLimit(gasWanted)).
    WithPriority(minPriority)
```

The current implementation uses an `InfiniteGasMeterWithLimit` which
tracks gas consumption throughout the transaction and then brings up an infinitegasmeter and is not enforced in a way that restricts consumption.
https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/eth/gas_limit.go#L65-L72

```go
type InfiniteGasMeter struct {
	consumed sdk.Gas
	limit sdk.Gas
}

```

Issue however is that the currrent approach has additional gas cost attached for the operations which doesn’t accurately reflect EVM-specific gas consumption since it doesn’t track the gas consumption at the end of the EVM transaction.

### Impact

QA, considering this seems to be currently the intended behavior.

### Recommended Mitigation Steps

Consider accounting for the gas cost at the end of the EVM transaction and not using only the infinite gas meter.

## QA-05 Journal can't be easily reset

### Proof of Concept

Nibiru's journal implementation lacks the `reset()` function present in go-ethereum. While both implementations have `newJournal()`, go-ethereum specifically includes `reset()` for performance optimization:

Note that the optimization in this case is the fact that `reset()`clears the journal and then after this operation the journal can be used anew. It is semantically similar to calling 'newJournal', but the underlying slices
can be reused.

```go
// Go-Ethereum Implementation
func (j *journal) reset() {
    j.entries = j.entries[:0]
    j.validRevisions = j.validRevisions[:0]
    clear(j.dirties)
    j.nextRevisionId = 0
}



// Nibiru Implementation
// Only has newJournal, missing reset
func newJournal() *journal {
    return &journal{
        dirties: make(map[common.Address]int),
    }
}
```

### Impact

QA new journals can still be created however previousslices can't be used without being set again.

### Recommended Mitigation

1. Implement reset functionality:

```go
func (j *journal) reset() {
    // Reuse existing slice capacity
    j.entries = j.entries[:0]
    j.validRevisions = j.validRevisions[:0]
    // Clear map without reallocating
    for k := range j.dirties {
        delete(j.dirties, k)
    }
    j.nextRevisionId = 0
}
```

## QA-06 DOSing by spamming transactions is allowed

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/keeper.go#L120-L124

```go
func (k Keeper) BaseFeeMicronibiPerGas(_ sdk.Context) *big.Int {
	return evm.BASE_FEE_MICRONIBI
}
```

Note that here `BaseFeeMicronibiPerGas` returns the gas base fee in units of the EVM denom and this is stored as a constant `1`.

See https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/const.go#L13-L19

```go
// BASE_FEE_MICRONIBI is the global base fee value for the network. It has a
// constant value of 1 unibi (micronibi) == 10^12 wei.
var (
	BASE_FEE_MICRONIBI = big.NewInt(1)
	BASE_FEE_WEI       = NativeToWei(BASE_FEE_MICRONIBI)
)

```

We can see that the gas base fee is 1 micronibi per gas.

To put this into essence this then means that regardless of the congestion of the network, the base fee is always 1 micronibi per gas. This then means that any malicio` can spam the network with multiple transactions and pay very minute fees.

### Impact

QA, since the user would still have to pay the gas cost.

### Recommended Mitigation Steps

Consider using a more dynamic base fee based on congestion of the network.

## QA-07 Some lower decimal tokens cannot be transferred in Nibiru

### Proof of Concept

Take a look at [x/evm/keeper/erc20.go](https://github.com/code-423n4/2024-11-nibiru/blob/main/x/evm/keeper/erc20.go):

```go
// Transfer sends ERC20 tokens from one account to another
func (e ERC20) Transfer(
    contractAddr gethcommon.Address,
    from gethcommon.Address,
    to gethcommon.Address,
    amount *big.Int,
    ctx sdk.Context,
) (*big.Int, *types.MsgEthereumTxResponse, error) {
    // ... transfer logic ...

    // Amount is always handled in wei (10^18)
    if amount.Cmp(big.NewInt(1e12)) < 0 {
        return nil, nil, fmt.Errorf("amount too small, minimum transfer is 10^12 wei")
    }
}
```

And in [x/evm/types/params.go](https://github.com/code-423n4/2024-11-nibiru/blob/main/x/evm/types/params.go):

```go
const (
    // DefaultEVMDenom defines the default EVM denomination on Nibiru: unibi
    DefaultEVMDenom = "unibi"
    // WeiFactor is the factor between wei and unibi (10^12)
    WeiFactor = 12
)
```

The protocol enforces a minimum transfer amount of 10^12 wei, which creates issues for tokens with decimals less than 18. For example:

1. USDC (6 decimals): 1 USDC = 10^6 units
2. WBTC (8 decimals): 1 WBTC = 10^8 units

These tokens cannot be transferred in small amounts because their decimal places are below the minimum transfer threshold.

### Impact

MEDIUM. The strict minimum transfer requirement of 10^12 wei causes:

1. Inability to transfer small amounts of low-decimal tokens
2. Poor UX for common stablecoins like USDC and USDT
3. Limited functionality for tokens with < 18 decimals
4. Potential adoption barriers for DeFi protocols that rely on precise token amounts
5. Incompatibility with existing Ethereum token standards and practices

### Recommended Mitigation Steps

1. Implement decimal-aware transfer minimums:

```go
func (e ERC20) Transfer(...) {
    decimals, err := e.Decimals(contractAddr, ctx)
    if err != nil {
        return nil, nil, err
    }

    // Adjust minimum based on token decimals
    minTransfer := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)-6), nil)
    if amount.Cmp(minTransfer) < 0 {
        return nil, nil, fmt.Errorf("amount too small, minimum transfer is %s", minTransfer)
    }
}
```

2. Add configuration option for minimum transfer amounts per token:

```go
type TokenConfig struct {
    MinTransferAmount *big.Int
    Decimals         uint8
}

func (e ERC20) GetTokenConfig(contractAddr common.Address) TokenConfig {
    // Return custom configuration per token
}
```

3. Document the limitation clearly in the protocol specifications if it must be maintained:

```markdown
## Token Transfer Limitations

- Minimum transfer amount: 10^12 wei
- Affects tokens with < 18 decimals
- Consider aggregating smaller amounts before transfer
```

4. Consider removing the minimum transfer restriction entirely to maintain full ERC20 compatibility.

## QA-08 Fix typos (Multiple instances)

### Proof of Concept

Take a look at

1. https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_emit_event_test.go#L68-L76

```go
			// TX hash attr must present
			attr, ok := event.GetAttribute(evm.PendingEthereumTxEventAttrEthHash)
			s.Require().True(ok, "tx hash attribute not found")
			s.Require().Equal(txMsg.Hash, attr.Value)

			// TX index attr must present
			attr, ok = event.GetAttribute(evm.PendingEthereumTxEventAttrIndex)
			s.Require().True(ok, "tx index attribute not found")
			s.Require().Equal("0", attr.Value)
```

Change to:
https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_emit_event_test.go#L68-L76

```diff
-			// TX hash attr must present
+			// TX hash attr must bepresent
			attr, ok := event.GetAttribute(evm.PendingEthereumTxEventAttrEthHash)
			s.Require().True(ok, "tx hash attribute not found")
			s.Require().Equal(txMsg.Hash, attr.Value)

-			// TX index attr must present
+			// TX index attr must be present
			attr, ok = event.GetAttribute(evm.PendingEthereumTxEventAttrIndex)
			s.Require().True(ok, "tx index attribute not found")
			s.Require().Equal("0", attr.Value)
```

### Impact

QA

### Recommended Mitigation Steps

Fix the typos.

## QA-09 MKR and its like of tokens that return `bytes32` would be broken when integrated

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/erc20.go#L147-L164:

```go

func (k Keeper) LoadERC20Name(
	ctx sdk.Context, abi *gethabi.ABI, erc20 gethcommon.Address,
) (out string, err error) {
	return k.LoadERC20String(ctx, abi, erc20, "name")
}

func (k Keeper) LoadERC20Symbol(
	ctx sdk.Context, abi *gethabi.ABI, erc20 gethcommon.Address,
) (out string, err error) {
	return k.LoadERC20String(ctx, abi, erc20, "symbol")
}

func (k Keeper) LoadERC20Decimals(
	ctx sdk.Context, abi *gethabi.ABI, erc20 gethcommon.Address,
) (out uint8, err error) {
	return k.loadERC20Uint8(ctx, abi, erc20, "decimals")
}
```

These are helper functions that are used to load the name, symbol, and decimals of an ERC20 token contract and they help within NIbiru's scope in ensuring functionalities execute as expected, for eg we can see it being used in funtoken's implementation:

https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/funtoken_from_erc20.go#L26-L52

```go
func (k Keeper) FindERC20Metadata(
	ctx sdk.Context,
	contract gethcommon.Address,
) (info *ERC20Metadata, err error) {
	// Load name, symbol, decimals
	name, err := k.LoadERC20Name(ctx, embeds.SmartContract_ERC20Minter.ABI, contract)
	if err != nil {
		return nil, err
	}

	symbol, err := k.LoadERC20Symbol(ctx, embeds.SmartContract_ERC20Minter.ABI, contract)
	if err != nil {
		return nil, err
	}

	decimals, err := k.LoadERC20Decimals(ctx, embeds.SmartContract_ERC20Minter.ABI, contract)
	if err != nil {
		return nil, err
	}

	return &ERC20Metadata{
		Name:     name,
		Symbol:   symbol,
		Decimals: decimals,
	}, nil
}

```

Issue however is that there is a wrong assumption that all tokens return their metadata using `string` which is wrong, this then means that when tokens that have their metadata as `bytes` are used, the functionality would be broken due to a revert that occurs when trying to load the string from here, because of the type mismatch, i.e `bytess` != `string`.

https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/erc20.go#L166-L194

```go
func (k Keeper) LoadERC20String(
	ctx sdk.Context,
	erc20Abi *gethabi.ABI,
	erc20Contract gethcommon.Address,
	methodName string,
) (out string, err error) {
	res, err := k.CallContract(
		ctx,
		erc20Abi,
		evm.EVM_MODULE_ADDRESS,
		&erc20Contract,
		false,
		Erc20GasLimitQuery,
		methodName,
	)
	if err != nil {
		return out, err
	}

	erc20Val := new(ERC20String)
	err = erc20Abi.UnpackIntoInterface(
		erc20Val, methodName, res.Ret,
	)
	if err != nil {
		return out, err
	}
	return erc20Val.Value, err
}

```

Evidently we expect a string value from `ERC20String` for `erc20Val` however for tokens such as [MKR](https://etherscan.io/address/0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2#readContract#F7) that have metadata fields `(name / symbol)` encoded as `bytes32` instead of a `string`, this flow wouldn't work.

### Impact

Since we have broken integration for some supported tokens cause when creating the fun token mapping for these tokens we meet an error [here in the function `createFunTokenFromERC20`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/funtoken_from_erc20.go#L104).

> NB: [`createFunTokenFromERC20` and `createFunTokenFromCoin` areboth called in `CreateFunToken()`](https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/msg_server.go#L424-L465).

And this window also breaks one of the core invariants stated by Nibiru, (see "4" below):

https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/README.md#L179

```markdown
## Main Invariants

.. snip 3. Any bank coin on Nibiru can be used to create a canonical ERC20 representation, for which the EVM itself (the module account) will be the owner. 4. Similar to (3), any ERC20 on Nibiru can be used to create a canonical bank coin representation. The owner of the ERC20 is unbounded, while only the EVM Module account can mint the bank coin representation produced.
```

### Recommended Mitigation Steps

Consider outrightly stating that not all tokens are supported, or support two types of metadata, i.e `string` and `bytes`.

## QA-10 Getting the code still leads to a panic that could crash the node

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/statedb.go#L39-L45

```go
func (k *Keeper) GetCode(ctx sdk.Context, codeHash gethcommon.Hash) []byte {
	codeBz, err := k.EvmState.ContractBytecode.Get(ctx, codeHash.Bytes())
	if err != nil {
		panic(err) // TODO: We don't like to panic.
	}
	return codeBz
}
```

This function is used to retrieve the bytecode of a smart contract. However, it panics if the code cannot be found. This is a bug as it should return an error instead of panicking, this can also be seen to be the intended use case per the TODO comment, considering the fact that this functionality is directly called via the `the gRPC query for "/eth.evm.v1.Query/Code"`: https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/grpc_query.go#L186-L218

```go
func (k Keeper) Code(
	goCtx context.Context, req *evm.QueryCodeRequest,
) (*evm.QueryCodeResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	address := gethcommon.HexToAddress(req.Address)
	acct := k.GetAccountWithoutBalance(ctx, address)

	var code []byte
	if acct != nil && acct.IsContract() {
		code = k.GetCode(ctx, gethcommon.BytesToHash(acct.CodeHash))
	}

	return &evm.QueryCodeResponse{
		Code: code,
	}, nil
}

```

### Impact

QA, since this is covered by a TODO, however this means that anyone attempting to get code for multiple ethereum addresses would lead to a panic and potentially crash the node.

### Recommended Mitigation Steps

Remove the panic and change the function to return an error instead.

## QA-11 Missing CheckTx optimization in account verification leads to redundant processing

### Proof of Concept

In Nibiru's `app/evmante/evmante_verify_eth_acc.go`, the account verification decorator processes transactions regardless of whether it's in `CheckTx` phase or not:

```go
// Nibiru's implementation - Missing optimization
func (anteDec AnteDecVerifyEthAcc) AnteHandle(
    ctx sdk.Context,
    tx sdk.Tx,
    simulate bool,
    next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
    // Processes ALL transactions without checking phase
    for i, msg := range tx.GetMsgs() {
        // ... validation logic ...
    }
    return next(ctx, tx, simulate)
}
```

Compare this with Ethermint's optimized implementation:

```go
// Ethermint's implementation
func (avd EthAccountVerificationDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
    // Skip expensive validation during block execution
    if !ctx.IsCheckTx() {
        return next(ctx, tx, simulate)
    }

    // Only process during CheckTx phase
    for _, msg := range tx.GetMsgs() {
        // ... validation logic ...
    }
    return next(ctx, tx, simulate)
}
```

### Impact

Low. While this doesn't introduce direct security vulnerabilities, it leads to:

Redundant processing of the same transaction once during `CheckTx` (mempool admission) and again say during `DeliverTx` (block execution)

Increased gas consumption which causes higher computational load during block processing
and potential block production slowdown.

### Recommended Mitigation Steps

Add the CheckTx phase validation:

```go
func (anteDec AnteDecVerifyEthAcc) AnteHandle(
    ctx sdk.Context,
    tx sdk.Tx,
    simulate bool,
    next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
    // Skip expensive validation if not in CheckTx phase
    if !ctx.IsCheckTx() {
        return next(ctx, tx, simulate)
    }

    // Only process during CheckTx
    for i, msg := range tx.GetMsgs() {
        // ... existing validation logic ...
    }
    return next(ctx, tx, simulate)
}
```

## QA-12 FunToken currently hardens off-chain tracking

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/precompile/funtoken.go#L109-L211

```go
func (p precompileFunToken) sendToBank(
	startResult OnRunStartResult,
	caller gethcommon.Address,
	readOnly bool,
) (bz []byte, err error) {
	ctx, method, args := startResult.CacheCtx, startResult.Method, startResult.Args
	if err := assertNotReadonlyTx(readOnly, method); err != nil {
		return nil, err
	}

	erc20, amount, to, err := p.parseArgsSendToBank(args)
	if err != nil {
		return
	}

	var evmResponses []*evm.MsgEthereumTxResponse

	// ERC20 must have FunToken mapping
	funtokens := p.evmKeeper.FunTokens.Collect(
		ctx, p.evmKeeper.FunTokens.Indexes.ERC20Addr.ExactMatch(ctx, erc20),
	)
	if len(funtokens) != 1 {
		err = fmt.Errorf("no FunToken mapping exists for ERC20 \"%s\"", erc20.Hex())
		return
	}
	funtoken := funtokens[0]

	// Amount should be positive
	if amount == nil || amount.Cmp(big.NewInt(0)) != 1 {
		return nil, fmt.Errorf("transfer amount must be positive")
	}

	// The "to" argument must be a valid Nibiru address
	toAddr, err := sdk.AccAddressFromBech32(to)
	if err != nil {
		return nil, fmt.Errorf("\"to\" is not a valid address (%s): %w", to, err)
	}

	// Caller transfers ERC20 to the EVM account
	transferTo := evm.EVM_MODULE_ADDRESS
	gotAmount, transferResp, err := p.evmKeeper.ERC20().Transfer(erc20, caller, transferTo, amount, ctx)
	if err != nil {
		return nil, fmt.Errorf("error in ERC20.transfer from caller to EVM account: %w", err)
	}
	evmResponses = append(evmResponses, transferResp)

	// EVM account mints FunToken.BankDenom to module account
	coinToSend := sdk.NewCoin(funtoken.BankDenom, math.NewIntFromBigInt(gotAmount))
	if funtoken.IsMadeFromCoin {
		// If the FunToken mapping was created from a bank coin, then the EVM account
		// owns the ERC20 contract and was the original minter of the ERC20 tokens.
		// Since we're sending them away and want accurate total supply tracking, the
		// tokens need to be burned.
		burnResp, e := p.evmKeeper.ERC20().Burn(erc20, evm.EVM_MODULE_ADDRESS, gotAmount, ctx)
		if e != nil {
			err = fmt.Errorf("ERC20.Burn: %w", e)
			return
		}
		evmResponses = append(evmResponses, burnResp)
	} else {
		// NOTE: The NibiruBankKeeper needs to reference the current [vm.StateDB] before
		// any operation that has the potential to use Bank send methods. This will
		// guarantee that [evmkeeper.Keeper.SetAccBalance] journal changes are
		// recorded if wei (NIBI) is transferred.
		p.evmKeeper.Bank.StateDB = startResult.StateDB
		err = p.evmKeeper.Bank.MintCoins(ctx, evm.ModuleName, sdk.NewCoins(coinToSend))
		if err != nil {
			return nil, fmt.Errorf("mint failed for module \"%s\" (%s): contract caller %s: %w",
				evm.ModuleName, evm.EVM_MODULE_ADDRESS.Hex(), caller.Hex(), err,
			)
		}
	}

	// Transfer the bank coin
	//
	// NOTE: The NibiruBankKeeper needs to reference the current [vm.StateDB] before
	// any operation that has the potential to use Bank send methods. This will
	// guarantee that [evmkeeper.Keeper.SetAccBalance] journal changes are
	// recorded if wei (NIBI) is transferred.
	p.evmKeeper.Bank.StateDB = startResult.StateDB
	err = p.evmKeeper.Bank.SendCoinsFromModuleToAccount(
		ctx,
		evm.ModuleName,
		toAddr,
		sdk.NewCoins(coinToSend),
	)
	if err != nil {
		return nil, fmt.Errorf("send failed for module \"%s\" (%s): contract caller %s: %w",
			evm.ModuleName, evm.EVM_MODULE_ADDRESS.Hex(), caller.Hex(), err,
		)
	}
	for _, resp := range evmResponses {
		for _, log := range resp.Logs {
			startResult.StateDB.AddLog(log.ToEthereum())
		}
	}

	// TODO: UD-DEBUG: feat: Emit EVM events
	// TODO: emit event for balance change of sender
	// TODO: emit event for balance change of recipient

	return method.Outputs.Pack(gotAmount)
}
```

Evidentlyy, we can see thereis a failure to emit events for critical state changes, even in the `sendToBank` function where token balances are modified.

### Impact

QA, albeit without events, it becomes difficult to track and verify token transfers off-chain which users of Nibiru would want to do.

### Recommended Mitigation Steps

Consider implementing proper event emission in the `sendToBank` function:

For e.g:

```go
func (p precompileFunToken) sendToBank(...) {
    // ... existing code ...

    // Emit events for balance changes
    ctx.EventManager().EmitEvent(
        sdk.NewEvent(
            "fun_token_transfer",
            sdk.NewAttribute("sender", caller.String()),
            sdk.NewAttribute("recipient", toAddr.String()),
            sdk.NewAttribute("amount", amount.String()),
            sdk.NewAttribute("erc20_address", erc20.String()),
            sdk.NewAttribute("bank_denom", funtoken.BankDenom),
        ),
    )

    // Add EVM logs for Ethereum compatibility
    startResult.StateDB.AddLog(&ethtypes.Log{
        Address: erc20,
        Topics: []common.Hash{
            common.BytesToHash([]byte("Transfer")),
            common.BytesToHash(caller.Bytes()),
            common.BytesToHash(toAddr.Bytes()),
        },
        Data:    common.BigToHash(amount).Bytes(),
        BlockNumber: uint64(ctx.BlockHeight()),
    })
}
```

## QA-13 Make `evmante_sigverify#AnteHandle()` more efficient

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/app/evmante/evmante_sigverify.go#L33-L74

```go
func (esvd EthSigVerificationDecorator) AnteHandle(
	ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	chainID := esvd.evmKeeper.EthChainID(ctx)
	ethCfg := evm.EthereumConfig(chainID)
	blockNum := big.NewInt(ctx.BlockHeight())
	signer := gethcore.MakeSigner(ethCfg, blockNum)

	for _, msg := range tx.GetMsgs() {
		msgEthTx, ok := msg.(*evm.MsgEthereumTx)
		if !ok {
			return ctx, errors.Wrapf(
				sdkerrors.ErrUnknownRequest,
				"invalid message type %T, expected %T", msg, (*evm.MsgEthereumTx)(nil),
			)
		}

		allowUnprotectedTxs := false
		ethTx := msgEthTx.AsTransaction()
		if !allowUnprotectedTxs && !ethTx.Protected() {
			return ctx, errors.Wrapf(
				sdkerrors.ErrNotSupported,
				"rejected unprotected Ethereum transaction. "+
					"Please EIP155 sign your transaction to protect it against replay-attacks",
			)
		}

		sender, err := signer.Sender(ethTx)
		if err != nil {
			return ctx, errors.Wrapf(
				sdkerrors.ErrorInvalidSigner,
				"couldn't retrieve sender address from the ethereum transaction: %s",
				err.Error(),
			)
		}

		// set up the sender to the transaction field if not already
		msgEthTx.From = sender.Hex()
	}

	return next(ctx, tx, simulate)
}
```

Evidently we can see that `allowUnprotectedTxs` is contantly set to `false` and then there is a next check that if `allowUnprotectedTxs` is false and then the transaction is not protected, then it returns an error, however since we already have `allowUnprotectedTxs` to always be false since it's set in the context then there is no need for this overcomputation.

### Impact

QA

### Recommended Mitigation Steps

Remove the setting of `allowUnprotectedTxs` to always be false and the check over all since it's not needed, i.e:

```diff
func (esvd EthSigVerificationDecorator) AnteHandle(
	ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	chainID := esvd.evmKeeper.EthChainID(ctx)
	ethCfg := evm.EthereumConfig(chainID)
	blockNum := big.NewInt(ctx.BlockHeight())
	signer := gethcore.MakeSigner(ethCfg, blockNum)

	for _, msg := range tx.GetMsgs() {
		msgEthTx, ok := msg.(*evm.MsgEthereumTx)
		if !ok {
			return ctx, errors.Wrapf(
				sdkerrors.ErrUnknownRequest,
				"invalid message type %T, expected %T", msg, (*evm.MsgEthereumTx)(nil),
			)
		}

-		allowUnprotectedTxs := false
		ethTx := msgEthTx.AsTransaction()
-		if !allowUnprotectedTxs && !ethTx.Protected() {
+		if !ethTx.Protected() {
			return ctx, errors.Wrapf(
				sdkerrors.ErrNotSupported,
				"rejected unprotected Ethereum transaction. "+
					"Please EIP155 sign your transaction to protect it against replay-attacks",
			)
		}

		sender, err := signer.Sender(ethTx)
		if err != nil {
			return ctx, errors.Wrapf(
				sdkerrors.ErrorInvalidSigner,
				"couldn't retrieve sender address from the ethereum transaction: %s",
				err.Error(),
			)
		}

		// set up the sender to the transaction field if not already
		msgEthTx.From = sender.Hex()
	}

	return next(ctx, tx, simulate)
}
```
