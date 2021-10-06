//go:build gofuzzbeta
// +build gofuzzbeta

package networkfuzz_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tharsis/ethermint/app"
	"github.com/tharsis/ethermint/crypto/ethsecp256k1"
	"github.com/tharsis/ethermint/tests"
	"github.com/tharsis/ethermint/testutil/network"
	"github.com/tharsis/ethermint/x/evm"
	evmtypes "github.com/tharsis/ethermint/x/evm/types"
)

func FuzzEVMHandler(f *testing.F) {
	f.Fuzz(func(t *testing.T, amount1 int64, gasLimit1 uint64, gasPrice1 int64, input1 []byte,
		amount2 int64, nonce2 uint64, gasLimit2 uint64, gasPrice2 int64, input2 []byte,
		amount3 int64, gasLimit3 uint64, gasPrice3 int64, input3 []byte) {
		checkTx := false
		evmApp := app.Setup(checkTx)
		ctx := evmApp.BaseApp.NewContext(checkTx, tmproto.Header{Height: 1, ChainID: "ethermint_9000-1", Time: time.Now().UTC()})
		evmApp.EvmKeeper.WithContext(ctx)
		handler := evm.NewHandler(evmApp.EvmKeeper)
		chainID := evmApp.EvmKeeper.ChainID()
		privKey, _ := ethsecp256k1.GenerateKey()
		sto := sdk.AccAddress(privKey.PubKey().Address())

		privKey, _ = ethsecp256k1.GenerateKey()

		signer := tests.NewSigner(privKey)
		ethSigner := ethtypes.LatestSignerForChainID(chainID)
		from := common.BytesToAddress(privKey.PubKey().Address().Bytes())
		to := common.BytesToAddress(sto)
		tx1 := evmtypes.NewTxContract(chainID, 0, big.NewInt(amount1), gasLimit1, big.NewInt(gasPrice1), input1, nil)
		tx1.From = from.String()
		tx1.Sign(ethSigner, signer)

		tx2 := evmtypes.NewTx(chainID, nonce2, &to, big.NewInt(amount2), gasLimit2, big.NewInt(gasPrice2), input2, nil)
		tx2.From = from.String()

		tx2.Sign(ethSigner, signer)

		tx3 := evmtypes.NewTx(chainID, 1, &to, big.NewInt(amount3), gasLimit3, big.NewInt(gasPrice3), input3, nil)
		tx3.From = from.String()

		tx3.Sign(ethSigner, signer)
		handler(ctx, tx1)
		handler(ctx, tx2)
		handler(ctx, tx3)
	})
}

func FuzzNetworkRPC(f *testing.F) {
	f.Fuzz(func(t *testing.T, msg []byte) {
		ethjson := new(ethtypes.Transaction)
		binerr := ethjson.UnmarshalBinary(msg)
		if binerr == nil {
			testnetwork := network.New(t, network.DefaultConfig())
			defer testnetwork.Cleanup()
			_, err := testnetwork.WaitForHeight(1)
			if err != nil {
				t.Log("failed to start up the network")
			} else if testnetwork.Validators != nil && len(testnetwork.Validators) > 0 && testnetwork.Validators[0].JSONRPCClient != nil {
				testnetwork.Validators[0].JSONRPCClient.SendTransaction(context.Background(), ethjson)
				h, err := testnetwork.WaitForHeightWithTimeout(10, time.Minute)
				if err != nil {
					t.Fatalf("expected to reach 10 blocks; got %d", h)
				}
				latestHeight, err := testnetwork.LatestHeight()
				if err != nil {
					t.Fatalf("latest height failed")
				}
				if latestHeight < h {
					t.Errorf("latestHeight should be greater or equal to")
				}
			}
		}
	})
}
