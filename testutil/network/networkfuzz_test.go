//go:build gofuzzbeta
// +build gofuzzbeta

package network

import (
	// "context"
	"math/big"
	"testing"
	"time"

	// "github.com/ethereum/go-ethereum/ethclient"

	abci "github.com/tendermint/tendermint/abci/types"
	tmjson "github.com/tendermint/tendermint/libs/json"

	"github.com/cosmos/cosmos-sdk/simapp"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/tharsis/ethermint/app"
	"github.com/tharsis/ethermint/crypto/ethsecp256k1"
	"github.com/tharsis/ethermint/tests"
	ethermint "github.com/tharsis/ethermint/types"
	"github.com/tharsis/ethermint/x/evm"
	"github.com/tharsis/ethermint/x/evm/types"

	"github.com/tendermint/tendermint/crypto/tmhash"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmversion "github.com/tendermint/tendermint/proto/tendermint/version"

	"github.com/tendermint/tendermint/version"
)

func FuzzABCI(f *testing.F) {
	f.Fuzz(func(t *testing.T, msg []byte) {
		eapp, ctx, _, _ := setupApp(t)
		tmheader := ctx.BlockHeader()
		eapp.BeginBlock(abci.RequestBeginBlock{
			Header: tmheader,
		})
		eapp.DeliverTx(abci.RequestDeliverTx{
			Tx: msg,
		})
		endBR := abci.RequestEndBlock{Height: tmheader.Height}
		eapp.EndBlocker(ctx, endBR)
		eapp.Commit()
	})
}

func FuzzNetworkAnyRPC(f *testing.F) {
	testnetwork := NewMini()
	methods := []string{
		"eth_getBlockByHash",
		"eth_getBlockByNumber",
		"eth_getBlockTransactionCountByHash",
		"eth_getBlockTransactionCountByNumber",
		"eth_getUncleCountByBlockHash",
		"eth_getUncleCountByBlockNumber",
		"eth_protocolVersion",
		"eth_syncing",
		"eth_coinbase",
		"eth_accounts",
		"eth_blockNumber",
		"eth_call",
		"eth_estimateGas",
		"eth_gasPrice",
		"eth_feeHistory",
		"eth_newFilter",
		"eth_newBlockFilter",
		"eth_newPendingTransactionFilter",
		"eth_uninstallFilter",
		"eth_getFilterChanges",
		"eth_getFilterLogs",
		"eth_getLogs",
		"eth_mining",
		"eth_hashrate",
		"eth_getWork",
		"eth_submitWork",
		"eth_submitHashrate",
		"eth_sign",
		"eth_signTransaction",
		"eth_getBalance",
		"eth_getStorageAt",
		"eth_getTransactionCount",
		"eth_getCode",
		"eth_sendTransaction",
		"eth_sendRawTransaction",
		"eth_getTransactionByHash",
		"eth_getTransactionByBlockHashAndIndex",
		"eth_getTransactionByBlockNumberAndIndex",
		"eth_getTransactionReceipt",
	}
	for _, method := range methods {
		f.Add(method, []byte{})
	}
	f.Fuzz(func(t *testing.T, method string, params []byte) {

		_, err := testnetwork.WaitForHeight(1)
		if err != nil {
			t.Log("failed to start up the network")
			testnetwork.Cleanup()
		} else {
			testnetwork.Validators[0].RawClient.CallRaw(nil, method, params)
			err := testnetwork.WaitForNextBlock()
			if err != nil {
				testnetwork.Cleanup()
				t.Fatalf("expected to reach the next block %v", err)
			}
		}
	})
}

func FuzzNetworkRPC(f *testing.F) {
	f.Fuzz(func(t *testing.T, msg []byte) {
		ethjson := new(ethtypes.Transaction)
		binerr := ethjson.UnmarshalBinary(msg)
		if binerr == nil {
			testnetwork := New(t, DefaultConfig())
			_, err := testnetwork.WaitForHeight(1)
			if err != nil {
				t.Log("failed to start up the network")
				testnetwork.Cleanup()
			} else {
				// client, err := ethclient.Dial(testnetwork.Validators[0].JSONRPCAddress)
				// if err != nil {
				// 	t.Log("failed to create a client")
				// } else {
				// 	client.SendTransaction(context.Background(), ethjson)
				testnetwork.Validators[0].EthRPCAPI.SendRawTransaction(msg)
				h, err := testnetwork.WaitForHeightWithTimeout(10, time.Minute)
				if err != nil {
					testnetwork.Cleanup()
					t.Fatalf("expected to reach 10 blocks; got %d", h)
				}
				latestHeight, err := testnetwork.LatestHeight()
				if err != nil {
					testnetwork.Cleanup()
					t.Fatalf("latest height failed")
				}
				if latestHeight < h {
					testnetwork.Cleanup()
					t.Errorf("latestHeight should be greater or equal to")
				}
			}
			testnetwork.Cleanup()
			// }
		}
	})
}

func setupApp(t *testing.T) (*app.EthermintApp, sdk.Context, keyring.Signer, common.Address) {
	checkTx := false
	// account key
	priv, err := ethsecp256k1.GenerateKey()
	require.NoError(t, err)
	address := common.BytesToAddress(priv.PubKey().Address().Bytes())
	signer := tests.NewSigner(priv)
	from := address
	// consensus key
	priv, err = ethsecp256k1.GenerateKey()
	require.NoError(t, err)
	consAddress := sdk.ConsAddress(priv.PubKey().Address())

	eapp := app.Setup(checkTx, nil)
	coins := sdk.NewCoins(sdk.NewCoin(types.DefaultEVMDenom, sdk.NewInt(100000000000000)))
	genesisState := app.ModuleBasics.DefaultGenesis(eapp.AppCodec())
	b32address := sdk.MustBech32ifyAddressBytes(sdk.GetConfig().GetBech32AccountAddrPrefix(), priv.PubKey().Address().Bytes())
	balances := []banktypes.Balance{
		{
			Address: b32address,
			Coins:   coins,
		},
		{
			Address: eapp.AccountKeeper.GetModuleAddress(authtypes.FeeCollectorName).String(),
			Coins:   coins,
		},
	}
	// update total supply
	bankGenesis := banktypes.NewGenesisState(banktypes.DefaultGenesisState().Params, balances, sdk.NewCoins(sdk.NewCoin(types.DefaultEVMDenom, sdk.NewInt(200000000000000))), []banktypes.Metadata{})
	genesisState[banktypes.ModuleName] = eapp.AppCodec().MustMarshalJSON(bankGenesis)

	stateBytes, err := tmjson.MarshalIndent(genesisState, "", " ")
	require.NoError(t, err)

	// Initialize the chain
	eapp.InitChain(
		abci.RequestInitChain{
			ChainId:         "ethermint_9000-1",
			Validators:      []abci.ValidatorUpdate{},
			ConsensusParams: simapp.DefaultConsensusParams,
			AppStateBytes:   stateBytes,
		},
	)

	ctx := eapp.BaseApp.NewContext(checkTx, tmproto.Header{
		Height:          1,
		ChainID:         "ethermint_9000-1",
		Time:            time.Now().UTC(),
		ProposerAddress: consAddress.Bytes(),
		Version: tmversion.Consensus{
			Block: version.BlockProtocol,
		},
		LastBlockId: tmproto.BlockID{
			Hash: tmhash.Sum([]byte("block_id")),
			PartSetHeader: tmproto.PartSetHeader{
				Total: 11,
				Hash:  tmhash.Sum([]byte("partset_header")),
			},
		},
		AppHash:            tmhash.Sum([]byte("app")),
		DataHash:           tmhash.Sum([]byte("data")),
		EvidenceHash:       tmhash.Sum([]byte("evidence")),
		ValidatorsHash:     tmhash.Sum([]byte("validators")),
		NextValidatorsHash: tmhash.Sum([]byte("next_validators")),
		ConsensusHash:      tmhash.Sum([]byte("consensus")),
		LastResultsHash:    tmhash.Sum([]byte("last_result")),
	})
	eapp.EvmKeeper.WithContext(ctx)

	queryHelper := baseapp.NewQueryServerTestHelper(ctx, eapp.InterfaceRegistry())
	types.RegisterQueryServer(queryHelper, eapp.EvmKeeper)

	acc := &ethermint.EthAccount{
		BaseAccount: authtypes.NewBaseAccount(sdk.AccAddress(address.Bytes()), nil, 0, 0),
		CodeHash:    common.BytesToHash(crypto.Keccak256(nil)).String(),
	}

	eapp.AccountKeeper.SetAccount(ctx, acc)

	valAddr := sdk.ValAddress(address.Bytes())
	validator, err := stakingtypes.NewValidator(valAddr, priv.PubKey(), stakingtypes.Description{})
	require.NoError(t, err)

	err = eapp.StakingKeeper.SetValidatorByConsAddr(ctx, validator)
	require.NoError(t, err)
	err = eapp.StakingKeeper.SetValidatorByConsAddr(ctx, validator)
	require.NoError(t, err)
	eapp.StakingKeeper.SetValidator(ctx, validator)

	return eapp, ctx, signer, from
}

func FuzzEVMHandler(f *testing.F) {
	f.Fuzz(func(t *testing.T, amount1 int64, gasLimit1 uint64, gasPrice1 int64, input1 []byte,
		amount2 int64, nonce2 uint64, gasLimit2 uint64, gasPrice2 int64, input2 []byte,
		amount3 int64, gasLimit3 uint64, gasPrice3 int64, input3 []byte) {

		eapp, ctx, signer, from := setupApp(t)

		ethSigner := ethtypes.LatestSignerForChainID(eapp.EvmKeeper.ChainID())
		handler := evm.NewHandler(eapp.EvmKeeper)

		to := crypto.CreateAddress(from, 1)
		chainID := big.NewInt(1)
		tx1 := types.NewTxContract(chainID, 0, big.NewInt(amount1), gasLimit1, big.NewInt(gasPrice1), nil, nil, input1, nil)
		tx1.From = from.String()
		tx1.Sign(ethSigner, signer)

		tx2 := types.NewTx(chainID, nonce2, &to, big.NewInt(amount2), gasLimit2, big.NewInt(gasPrice2), nil, nil, input2, nil)
		tx2.From = from.String()

		tx2.Sign(ethSigner, signer)

		tx3 := types.NewTx(chainID, 1, &to, big.NewInt(amount3), gasLimit3, big.NewInt(gasPrice3), nil, nil, input3, nil)
		tx3.From = from.String()

		tx3.Sign(ethSigner, signer)
		handler(ctx, tx1)
		handler(ctx, tx2)
		handler(ctx, tx3)
	})
}
