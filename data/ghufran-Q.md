https://github.com/code-423n4/2024-11-nibiru/blob/main/app/evmante/evmante_mempool_fees.go#L46

## Summary

The check for minGasPrice.IsZero() allows the transaction to proceed without checking the gas price if MinGasPrices is not set. Especially if there are fallback mechanisms that should enforce a minimum gas price even when MinGasPrices is zero.

## Vulnerability Detail

In the code, the MinGasPrices parameter is used to ensure that transactions include a sufficient gas price to be processed by the mempool. If the MinGasPrices is zero, the logic allows the transaction to proceed without any fee check, potentially resulting in transactions with insufficient fees being processed or accepted into the mempool. The issue arises when the MinGasPrices parameter (set in the mempool) is zero. In this case, the code assumes that no minimum gas price is required, and thus no validation is performed on the fee being sent with the transaction.While skipping the check might seem like a valid option in some cases, it introduces a critical issue if MinGasPrices is accidentally set to zero or remains uninitialized. This would allow transactions with very low (or zero) fees to be accepted into the mempool, which could have severe consequences.

## POC

If MinGasPrices is zero, the code skips the gas price validation entirely. This allows transactions with very low or zero gas prices to be accepted, potentially leading to network flooding

```go
func (d MempoolGasPriceDecorator) AnteHandle(
    ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
    // only run on CheckTx
    if !ctx.IsCheckTx() && !simulate {
        return next(ctx, tx, simulate)
    }

    minGasPrice := ctx.MinGasPrices().AmountOf(evm.EVMBankDenom)
    baseFeeMicronibi := d.evmKeeper.BaseFeeMicronibiPerGas(ctx)
    baseFeeMicronibiDec := math.LegacyNewDecFromBigInt(baseFeeMicronibi)

    // If MinGasPrices is zero, skip the fee check entirely
    if minGasPrice.IsZero() {
        return next(ctx, tx, simulate)
    } else if minGasPrice.LT(baseFeeMicronibiDec) {
        minGasPrice = baseFeeMicronibiDec
    }

    for _, msg := range tx.GetMsgs() {
        ethTx, ok := msg.(*evm.MsgEthereumTx)
        if !ok {
            return ctx, errors.Wrapf(
                sdkerrors.ErrUnknownRequest,
                "invalid message type %T, expected %T",
                msg, (*evm.MsgEthereumTx)(nil),
            )
        }

        baseFeeWei := evm.NativeToWei(baseFeeMicronibi)
        effectiveGasPriceDec := math.LegacyNewDecFromBigInt(
            evm.WeiToNative(ethTx.EffectiveGasPriceWeiPerGas(baseFeeWei)),
        )

        if effectiveGasPriceDec.LT(minGasPrice) {
            return ctx, errors.Wrapf(
                sdkerrors.ErrInsufficientFee,
                "provided gas price < minimum local gas price (%s < %s). "+
                    "Please increase the priority tip (for EIP-1559 txs) or the gas prices "+
                    "(for access list or legacy txs)",
                effectiveGasPriceDec, minGasPrice,
            )
        }
    }

    return next(ctx, tx, simulate)
}
```

## Impact

Validators would still need to process these low-fee transactions, leading to increased computational load and inefficiencies. This could affect the overall throughput of the system.

## Recommendation

It might be beneficial to implement a default gas price or additional checks when MinGasPrices is zero. 

```go
if minGasPrice.IsZero() {
    minGasPrice = baseFeeMicronibiDec  // Use a base fee if MinGasPrices is not set
}
```
