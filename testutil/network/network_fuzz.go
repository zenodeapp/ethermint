package network

import (
	"math/big"
	"time"

	"git.fuzzbuzz.io/fuzz"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tharsis/ethermint/app"
	"github.com/tharsis/ethermint/crypto/ethsecp256k1"
	"github.com/tharsis/ethermint/tests"
	"github.com/tharsis/ethermint/x/evm"
	evmtypes "github.com/tharsis/ethermint/x/evm/types"
)

// nolint
func FuzzEVMApp(f *fuzz.F) {
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
	tx1 := evmtypes.NewTxContract(chainID, 0, big.NewInt(f.Int64("amount1").Get()), f.Uint64("gasLimit1").Get(), big.NewInt(f.Int64("gasPrice1").Get()), f.Bytes("input1").Get(), nil)
	tx1.From = from.String()
	tx1.Sign(ethSigner, signer)

	tx2 := evmtypes.NewTx(chainID, f.Uint64("nonce2").Get(), &to, big.NewInt(f.Int64("amount2").Get()), f.Uint64("gasLimit2").Get(), big.NewInt(f.Int64("gasPrice2").Get()), f.Bytes("input2").Get(), nil)
	tx2.From = from.String()

	tx2.Sign(ethSigner, signer)

	tx3 := evmtypes.NewTx(chainID, 1, &to, big.NewInt(f.Int64("amount3").Get()), f.Uint64("gasLimit3").Get(), big.NewInt(f.Int64("gasPrice3").Get()), f.Bytes("input3").Get(), nil)
	tx3.From = from.String()

	tx3.Sign(ethSigner, signer)
	handler(ctx, tx1)
	handler(ctx, tx2)
	handler(ctx, tx3)
}

func FuzzNetworkRawRPC(f *fuzz.F) {
	FuzzEVMApp(f)
	// FIXME: reliable network initialization in the fuzzer environment
	// msg := f.Bytes("msg").Get()
	// ethjson := new(ethtypes.Transaction)
	// binerr := ethjson.UnmarshalBinary(msg)
	// if binerr == nil {
	// 	testnetwork := New(nil, DefaultConfig())
	// 	defer testnetwork.Cleanup()
	// 	_, err := testnetwork.WaitForHeight(1)
	// 	if err != nil {
	// 		f.Fail("failed to start up the network")
	// 	}
	// 	// nolint
	// 	testnetwork.Validators[0].JSONRPCClient.SendTransaction(context.Background(), ethjson)
	// 	h, err := testnetwork.WaitForHeightWithTimeout(10, time.Minute)
	// 	if err != nil {
	// 		f.Fail(fmt.Sprintf("expected to reach 10 blocks; got %d", h))
	// 	}
	// 	latestHeight, err := testnetwork.LatestHeight()
	// 	if err != nil {
	// 		f.Fail("latest height failed")
	// 	}
	// 	if latestHeight < h {
	// 		f.Fail("latestHeight should be greater or equal to")
	// 	}
	// }
}

func FuzzNetworkBackend(f *fuzz.F) {
	FuzzEVMApp(f)
	// FIXME: reliable network initialization in the fuzzer environment
	// al := &ethtypes.AccessList{}
	// sk := []ethcommon.Hash{}
	// f.Array("StorageKeys", &[]ethcommon.Hash{
	// 	ethcommon.BytesToHash(f.Bytes("Hash").Min(32).Max(32).Get()),
	// }).Populate(&sk)
	// f.Ptr("AccessList", &[]ethtypes.AccessTuple{{
	// 	Address:     ethcommon.BytesToAddress(f.Bytes("Address").Min(20).Max(20).Get()),
	// 	StorageKeys: []ethcommon.Hash{},
	// }}).Populate(&al)
	// to := ethcommon.BytesToAddress(f.Bytes("To").Min(20).Max(20).Get())
	// args := types.SendTxArgs{
	// 	From:       ethcommon.BytesToAddress(f.Bytes("From").Min(20).Max(20).Get()),
	// 	To:         &to,
	// 	Gas:        (*hexutil.Uint64)(f.Uint64Ptr("Gas").Get()),
	// 	GasPrice:   (*hexutil.Big)(big.NewInt(f.Int64("GasPrice").Get())),
	// 	Value:      (*hexutil.Big)(big.NewInt(f.Int64("Value").Get())),
	// 	Nonce:      (*hexutil.Uint64)(f.Uint64Ptr("Nonce").Get()),
	// 	Data:       (*hexutil.Bytes)(f.BytesPtr("Data").Get()),
	// 	Input:      (*hexutil.Bytes)(f.BytesPtr("Input").Get()),
	// 	ChainID:    (*hexutil.Big)(big.NewInt(f.Int64("ChainID").Get())),
	// 	AccessList: al,
	// }
	// testnetwork := New(nil, DefaultConfig())
	// defer testnetwork.Cleanup()
	// _, err := testnetwork.WaitForHeight(1)
	// if err != nil {
	// 	f.Fail("failed to start up the network")
	// }
	// // nolint
	// testnetwork.Validators[0].ETHbackend.SendTransaction(args)
	// h, err := testnetwork.WaitForHeightWithTimeout(10, time.Minute)
	// if err != nil {
	// 	f.Fail(fmt.Sprintf("expected to reach 10 blocks; got %d", h))
	// }
	// latestHeight, err := testnetwork.LatestHeight()
	// if err != nil {
	// 	f.Fail("latest height failed")
	// }
	// if latestHeight < h {
	// 	f.Fail("latestHeight should be greater or equal to")
	// }
}
