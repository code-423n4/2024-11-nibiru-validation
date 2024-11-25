### [L-01] Use of deprecated WrapSDKContext()
The function `WrapSDKContext()` has been marked as deprecated, as noted in its definition:  
[WrapSDKContext() source](https://github.com/cosmos/cosmos-sdk/blob/2d04a1af21424f9c6754592173b2c2a6cf986342/types/context.go#L386)

```go
// Deprecated: there is no need to wrap anymore as the Cosmos SDK context implements context.Context.
func WrapSDKContext(ctx Context) context.Context {
	return ctx
}
```

Despite its deprecation, the **Nibiru** project continues to use this function in several places. This practice is discouraged, as the Cosmos SDK context (`Context`) natively implements the `context.Context` interface, making the wrapping unnecessary.


### [L-02] Importing Deprecated `simapp` Package

The `simapp` package should not be imported into your application. Instead, the `runtime.AppI` interface should be used for defining apps, along with the `simtestutil` package for application testing.

However, the `simapp` package is imported and used in the **Nibiru** application:

This dependency should be replaced with the recommended `runtime.AppI` interface and `simtestutil` package to ensure compliance with updated SDK practices.

---

### [L-03] Incorrect Import of Protobuf

The Cosmos SDK has transitioned from `gogo/protobuf`, which is unmaintained, to its own maintained fork, `cosmos/gogoproto`. As such, imports from `github.com/gogo/protobuf` should be replaced with `github.com/cosmos/gogoproto`.

Currently, the **Nibiru** project still uses the outdated import:

### Recommendation:
- Replace all `gogo/protobuf` imports with `cosmos/gogoproto`.
- Remove the directive `replace github.com/gogo/protobuf => github.com/regen-network/protobuf`.
- Update dependencies to use the latest maintained `cosmos/gogoproto` version (currently `v1.5.0`). 

This will avoid potential dependency issues and align the project with the updated SDK standards.



### [L-04] Potential Issues in Event Handling in the Nibiru Project

The Nibiru project has some potential issues in event handling, mainly in the following areas:

---

**1. Inconsistency in EVM Transaction Events**

Example Code
```ts
const ownerBalanceBefore = await provider.getBalance(account);
const recipientBalanceBefore = await provider.getBalance(recipient);
expect(recipientBalanceBefore).toEqual(BigInt(0));

const tx = await contract[method](recipient, { value: weiToSend });
const receipt = await tx.wait(1, 5e3);

const tenPow12 = toBigInt(1e12);
const txCostMicronibi = weiToSend / tenPow12 + receipt.gasUsed;
const txCostWei = txCostMicronibi * tenPow12;
const expectedOwnerWei = ownerBalanceBefore - txCostWei;

const ownerBalanceAfter = await provider.getBalance(account);
const recipientBalanceAfter = await provider.getBalance(recipient);

console.debug(`DEBUG method ${method} %o:`, {
  ownerBalanceBefore,
  weiToSend,
  expectedOwnerWei,
  ownerBalanceAfter,
  recipientBalanceBefore,
  recipientBalanceAfter,
  gasUsed: receipt.gasUsed,
  gasPrice: `${receipt.gasPrice.toString()}`,
  to: receipt.to,
  from: receipt.from,
});
expect(recipientBalanceAfter).toBe(weiToSend);
const delta = ownerBalanceAfter - expectedOwnerWei;
const deltaFromExpectation = delta >= 0 ? delta : -delta;
expect(deltaFromExpectation).toBeLessThan(parseEther('0.1'));
```

Issues:
1. **Lack of EventTypeMessage Verification**: The emitted `EventTypeMessage` is not verified to ensure it includes required attributes like `module` and `sender`.
2. **No Assurance of Event Ordering**: There is no mechanism to guarantee that events are emitted in the correct sequence.
3. **Replay Protection Missing**: The emitted events are not protected against potential replay attacks.

---

**2. Completeness of Cross-Chain Transfer Events**

Example Code
```sh
# Transfer tokens from nibiru-0 to nibiru-1
nibid tx ibc-transfer transfer transfer \
channel-0 \
nibi18mxturdh0mjw032c3zslgkw63cukkl4q5skk8g \
1000000unibi \
--from validator \
--fees 5000unibi \
--yes | jq
```

Issues:
1. **Missing Validation of Transfer Completion Events**: Cross-chain transfer completion events are not verified, leading to potential gaps in event tracking.
2. **No Consistency Checks Across Chains**: Events are not validated to ensure consistency between the source and destination chains.
3. **Potential Loss of Attributes**: Attributes critical to identifying the transfer might be lost or incomplete.

---

**3. Atomicity of Contract Call Events**

Example Code
```go
testContractAddr := deployResp.ContractAddr
testContractNibiAddr := eth.EthAddrToNibiruAddr(testContractAddr)

s.T().Log("Give the test contract 10 NIBI (native)")
s.Require().NoError(testapp.FundAccount(
	deps.App.BankKeeper,
	deps.Ctx,
	testContractNibiAddr,
	sdk.NewCoins(sdk.NewCoin(bankDenom, sdk.NewIntFromBigInt(sendAmt)))),
)

evmtest.AssertBankBalanceEqual(
	s.T(), deps, bankDenom, testContractAddr, sendAmt,
)
evmtest.AssertBankBalanceEqual(
	s.T(), deps, bankDenom, evm.EVM_MODULE_ADDRESS, big.NewInt(0),
)
```

Issues:
1. **Lack of Atomicity Between State Changes and Events**: State changes and event emissions are not guaranteed to happen atomically, potentially causing inconsistencies.
2. **No Rollback on Contract Call Failure**: If a contract call fails, emitted events are not rolled back.
3. **Insufficient Tracking Information in Events**: Events lack key operation details for auditing and debugging purposes.

---

**Recommended Improvements**

**1. Add Event Validation Middleware**
Introduce a middleware to validate events before and after message execution:
```go
// Middleware to validate events
func ValidateEventMiddleware(ctx sdk.Context, msg sdk.Msg, next sdk.Handler) error {
    // 1. Validate required attributes in the event
    if err := validateRequiredAttributes(msg); err != nil {
        return err
    }
    
    // 2. Execute the message handler
    err := next(ctx, msg)
    
    // 3. Validate emitted events
    if err := validateEmittedEvents(ctx.EventManager().Events()); err != nil {
        return err
    }
    
    return err
}
```

---

**2. Enhance Event Tracking**
Introduce a structured event tracking mechanism during critical operations:
```go
func (k Keeper) ExecuteContract(ctx sdk.Context, contract common.Address, ...) error {
    // Create an event trace
    trace := NewEventTrace(ctx, "execute_contract")
    defer trace.Close()
    
    // Add critical information to the trace
    trace.AddAttribute("contract", contract.String())
    trace.AddAttribute("sender", msg.Sender.String())
    
    // Perform the operation
    if err := k.doExecute(ctx, ...); err != nil {
        trace.SetError(err)
        return err
    }
    
    return nil
}
```

---

**3. Implement Event Consistency Checks**
Create a utility function to ensure event consistency:
```go
func ValidateEventConsistency(ctx sdk.Context, events sdk.Events) error {
    // 1. Check if required events are present
    if !hasRequiredEvents(events) {
        return ErrMissingRequiredEvents
    }
    
    // 2. Validate the order of events
    if err := validateEventOrder(events); err != nil {
        return err
    }
    
    // 3. Check event attribute completeness
    if err := validateEventAttributes(events); err != nil {
        return err
    }
    
    return nil
}
```


