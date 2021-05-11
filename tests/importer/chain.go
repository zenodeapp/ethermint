package importer

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/simapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/ibc/testing/mock"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	ethtypes "github.com/ethereum/go-ethereum/core/types"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/log"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"

	"github.com/cosmos/ethermint/app"
	"github.com/cosmos/ethermint/crypto/ethsecp256k1"
	rpctypes "github.com/cosmos/ethermint/ethereum/rpc/types"
	"github.com/cosmos/ethermint/types"
)

// Chain defines an Cosmos EVM chain used for testing purposes
type Chain struct {
	t *testing.T

	App           *app.EthermintApp
	ChainID       string          // full chain identifier of the chain which contains the epoch and the EIP155 chain ID
	EVMChainID    *big.Int        // EIP155 chain ID
	LastHeader    ethtypes.Header // ethereum formatted header for last block height committed
	CurrentHeader tmproto.Header  // header for current block height

	Validators *tmtypes.ValidatorSet
}

// NewChain initializes a new TestChain instance with a single validator set using a
// generated private key. It also creates a sender account to be used for delivering transactions.
//
// The first block height is committed to state in order to allow for client creations on
// counterparty chains. The TestChain will return with a block height starting at 2.
//
// Time management is handled by the Coordinator in order to ensure synchrony between chains.
// Each update of any chain increments the block header time for all chains by 5 seconds.
func NewChain(t *testing.T, chainID string) *Chain {
	// generate validator private/public key
	privVal := mock.NewPV()
	pubKey, err := privVal.GetPubKey()
	require.NoError(t, err)

	evmChainID, err := types.ParseChainID(chainID)
	require.NoError(t, err)

	// create validator set with single validator
	validator := tmtypes.NewValidator(pubKey, 1)
	valSet := tmtypes.NewValidatorSet([]*tmtypes.Validator{validator})

	// generate genesis account
	senderPrivKey, err := ethsecp256k1.GenerateKey()
	require.NoError(t, err)
	baseAcc := authtypes.NewBaseAccount(senderPrivKey.PubKey().Address().Bytes(), senderPrivKey.PubKey(), 0, 0)
	ethAccount := types.NewEthAccount(baseAcc, nil)
	balance := banktypes.Balance{
		Address: ethAccount.GetAddress().String(),
		Coins:   sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(100000000000000))),
	}

	app := SetupWithGenesisValSet(t, chainID, valSet, []authtypes.GenesisAccount{ethAccount}, balance)

	// create current header and call begin block
	header := tmproto.Header{
		ChainID: chainID,
		Height:  1,
		Time:    time.Now().UTC(),
	}

	// create an account to send transactions from
	chain := &Chain{
		t:             t,
		ChainID:       chainID,
		EVMChainID:    evmChainID,
		App:           app,
		LastHeader:    ethtypes.Header{},
		CurrentHeader: header,
		Validators:    valSet,
	}

	chain.CommitBlock()

	return chain
}

// GetContext returns the current context for the application.
func (chain *Chain) Context() sdk.Context {
	return chain.App.BaseApp.NewContext(false, chain.CurrentHeader)
}

func (chain *Chain) CommitBlock() {
	chain.App.Commit()
	chain.nextBlock()
}

// NextBlock sets the last header to the current header and increments the current header to be
// at the next block height. It does not update the time as that is handled by the Coordinator.
//
// CONTRACT: this function must only be called after app.Commit() occurs
func (chain *Chain) nextBlock() {
	// set the last header to the current header
	// use nil trusted fields
	tmHeader, _ := tmtypes.HeaderFromProto(&chain.CurrentHeader)

	chain.LastHeader = *rpctypes.EthHeaderFromTendermint(tmHeader)

	// increment the current header
	chain.CurrentHeader = tmproto.Header{
		ChainID:            chain.ChainID,
		Height:             chain.App.LastBlockHeight() + 1,
		AppHash:            chain.App.LastCommitID().Hash,
		Time:               chain.CurrentHeader.Time.Add(5 * time.Second).UTC(),
		ValidatorsHash:     chain.Validators.Hash(),
		NextValidatorsHash: chain.Validators.Hash(),
	}

	tmHeader, _ = tmtypes.HeaderFromProto(&chain.CurrentHeader)

	chain.App.BeginBlock(abci.RequestBeginBlock{
		Hash:   tmHeader.Hash(),
		Header: chain.CurrentHeader,
	})
}

func SetupTestingApp() (*app.EthermintApp, map[string]json.RawMessage) {
	db := dbm.NewMemDB()
	encCdc := app.MakeEncodingConfig()
	app := app.NewEthermintApp(log.NewNopLogger(), db, nil, true, map[int64]bool{}, app.DefaultNodeHome, 5, encCdc, simapp.EmptyAppOptions{})
	return app, simapp.NewDefaultGenesisState(encCdc.Marshaler)
}

// SetupWithGenesisValSet initializes a new SimApp with a validator set and genesis accounts
// that also act as delegators. For simplicity, each validator is bonded with a delegation
// of one consensus engine unit (10^6) in the default token of the simapp from first genesis
// account. A Nop logger is set in SimApp.
func SetupWithGenesisValSet(t *testing.T, chainID string, valSet *tmtypes.ValidatorSet, genAccs []authtypes.GenesisAccount, balances ...banktypes.Balance) *app.EthermintApp {
	evmApp, genesisState := SetupTestingApp()
	// set genesis accounts
	authGenesis := authtypes.NewGenesisState(authtypes.DefaultParams(), genAccs)
	genesisState[authtypes.ModuleName] = evmApp.AppCodec().MustMarshalJSON(authGenesis)

	validators := make([]stakingtypes.Validator, 0, len(valSet.Validators))
	delegations := make([]stakingtypes.Delegation, 0, len(valSet.Validators))

	bondAmt := sdk.NewInt(1000000)

	for _, val := range valSet.Validators {
		pk, err := cryptocodec.FromTmPubKeyInterface(val.PubKey)
		require.NoError(t, err)
		pkAny, err := codectypes.NewAnyWithValue(pk)
		require.NoError(t, err)
		validator := stakingtypes.Validator{
			OperatorAddress:   sdk.ValAddress(val.Address).String(),
			ConsensusPubkey:   pkAny,
			Jailed:            false,
			Status:            stakingtypes.Bonded,
			Tokens:            bondAmt,
			DelegatorShares:   sdk.OneDec(),
			Description:       stakingtypes.Description{},
			UnbondingHeight:   int64(0),
			UnbondingTime:     time.Unix(0, 0).UTC(),
			Commission:        stakingtypes.NewCommission(sdk.ZeroDec(), sdk.ZeroDec(), sdk.ZeroDec()),
			MinSelfDelegation: sdk.ZeroInt(),
		}
		validators = append(validators, validator)
		delegations = append(delegations, stakingtypes.NewDelegation(genAccs[0].GetAddress(), val.Address.Bytes(), sdk.OneDec()))

	}
	// set validators and delegations
	stakingGenesis := stakingtypes.NewGenesisState(stakingtypes.DefaultParams(), validators, delegations)
	genesisState[stakingtypes.ModuleName] = evmApp.AppCodec().MustMarshalJSON(stakingGenesis)

	totalSupply := sdk.NewCoins()
	for _, b := range balances {
		// add genesis acc tokens and delegated tokens to total supply
		totalSupply = totalSupply.Add(b.Coins.Add(sdk.NewCoin(sdk.DefaultBondDenom, bondAmt))...)
	}

	// add bonded amount to bonded pool module account
	balances = append(balances, banktypes.Balance{
		Address: authtypes.NewModuleAddress(stakingtypes.BondedPoolName).String(),
		Coins:   sdk.Coins{sdk.NewCoin(sdk.DefaultBondDenom, bondAmt)},
	})

	// update total supply
	bankGenesis := banktypes.NewGenesisState(banktypes.DefaultGenesisState().Params, balances, totalSupply, []banktypes.Metadata{})
	genesisState[banktypes.ModuleName] = evmApp.AppCodec().MustMarshalJSON(bankGenesis)

	stateBytes, err := json.MarshalIndent(genesisState, "", " ")
	require.NoError(t, err)

	// init chain will set the validator set and initialize the genesis accounts
	evmApp.InitChain(
		abci.RequestInitChain{
			ChainId:         chainID,
			Validators:      []abci.ValidatorUpdate{},
			ConsensusParams: app.DefaultConsensusParams,
			AppStateBytes:   stateBytes,
		},
	)

	header := tmproto.Header{
		ChainID:            chainID,
		Height:             evmApp.LastBlockHeight() + 1,
		AppHash:            evmApp.LastCommitID().Hash,
		ValidatorsHash:     valSet.Hash(),
		NextValidatorsHash: valSet.Hash(),
	}

	tmHeader, _ := tmtypes.HeaderFromProto(&header)

	// commit genesis changes
	evmApp.Commit()
	evmApp.BeginBlock(abci.RequestBeginBlock{
		Hash:   tmHeader.Hash(),
		Header: header,
	})

	return evmApp
}
