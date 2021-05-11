package importer

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"runtime/pprof"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cosmos/ethermint/core"

	ethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	ethcore "github.com/ethereum/go-ethereum/core"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	ethvm "github.com/ethereum/go-ethereum/core/vm"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	ethparams "github.com/ethereum/go-ethereum/params"
	ethrlp "github.com/ethereum/go-ethereum/rlp"
)

var (
	flagDataDir    string
	flagBlockchain string
	flagCPUProfile string

	genInvestor = ethcmn.HexToAddress("0x756F45E3FA69347A9A973A725E3C98bC4db0b5a0")

	rewardBig8  = big.NewInt(8)
	rewardBig32 = big.NewInt(32)
)

// func init() {
// 	flag.StringVar(&flagCPUProfile, "cpu-profile", "", "write CPU profile")
// 	flag.StringVar(&flagDataDir, "datadir", "tmp", "test data directory for state storage")
// 	flag.StringVar(&flagBlockchain, "blockchain", "blockchain", "ethereum block export file (blocks to import)")
// 	flag.Parse()
// }

type ImporterTestSuite struct {
	suite.Suite

	chain *Chain
}

func TestImporterTestSuite(t *testing.T) {
	suite.Run(t, new(ImporterTestSuite))
}

func (suite *ImporterTestSuite) SetupTest() {
	suite.chain = NewChain(suite.T(), "ethermint-1")
}

func cleanup() {
	fmt.Println("cleaning up test execution...")
	os.RemoveAll(flagDataDir)

	if flagCPUProfile != "" {
		pprof.StopCPUProfile()
	}
}

func trapSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		cleanup()
		os.Exit(1)
	}()
}

// nolint: interfacer
func (suite *ImporterTestSuite) createAndTestGenesis() {
	genBlock := ethcore.DefaultGenesisBlock()

	// sort the addresses and insertion of key/value pairs matters
	genAddrs := make([]string, len(genBlock.Alloc))
	i := 0
	for addr := range genBlock.Alloc {
		genAddrs[i] = addr.String()
		i++
	}

	sort.Strings(genAddrs)

	for _, addrStr := range genAddrs {
		addr := ethcmn.HexToAddress(addrStr)
		acc := genBlock.Alloc[addr]

		suite.chain.App.EvmKeeper.AddBalance(suite.chain.Context(), addr, acc.Balance)
		suite.chain.App.EvmKeeper.SetCode(suite.chain.Context(), addr, acc.Code)
		suite.chain.App.EvmKeeper.SetNonce(suite.chain.Context(), addr, acc.Nonce)

		for key, value := range acc.Storage {
			suite.chain.App.EvmKeeper.SetState(suite.chain.Context(), addr, key, value)
		}
	}
}

func (suite *ImporterTestSuite) TestImportBlocks() {
	if flagDataDir == "" {
		flagDataDir = os.TempDir()
	}

	if flagCPUProfile != "" {
		f, err := os.Create(flagCPUProfile)
		suite.Require().NoError(err, "failed to create CPU profile")

		err = pprof.StartCPUProfile(f)
		suite.Require().NoError(err, "failed to start CPU profile")
	}

	defer cleanup()
	trapSignals()

	// set and test genesis block
	// createAndTestGenesis(t, cms, ak, bk, suite.chain.App.EvmKeeper)

	// open blockchain export file
	blockchainInput, err := os.Open(flagBlockchain)
	suite.Require().NoError(err)

	defer func() {
		err := blockchainInput.Close()
		suite.Require().NoError(err)
	}()

	// ethereum mainnet config
	chainContext := core.NewChainContext()
	vmConfig := ethvm.Config{}
	chainConfig := ethparams.MainnetChainConfig

	// create RLP stream for exported blocks
	stream := ethrlp.NewStream(blockchainInput, 0)
	startTime := time.Now()

	var block ethtypes.Block
	for {
		err = stream.Decode(&block)
		if err == io.EOF {
			break
		}

		suite.Require().NoError(err, "failed to decode block")

		var (
			usedGas = new(uint64)
			gp      = new(ethcore.GasPool).AddGas(block.GasLimit())
		)

		header := block.Header()
		chainContext.Coinbase = header.Coinbase

		chainContext.SetHeader(block.NumberU64(), header)

		if chainConfig.DAOForkSupport && chainConfig.DAOForkBlock != nil && chainConfig.DAOForkBlock.Cmp(block.Number()) == 0 {
			suite.applyDAOHardFork()
		}

		for i, tx := range block.Transactions() {
			suite.chain.App.EvmKeeper.Prepare(suite.chain.Context(), tx.Hash(), block.Hash(), i)
			// suite.chain.App.EvmKeeper.CommitStateDB.Set(block.Hash())

			receipt, gas, err := suite.applyTransaction(
				chainConfig, chainContext, nil, gp, header, tx, usedGas, vmConfig,
			)
			suite.Require().NoError(err, "failed to apply tx at block %d; tx: %X; gas %d; receipt:%v", block.NumberU64(), tx.Hash(), gas, receipt)
			suite.Require().NotNil(receipt)
		}

		// apply mining rewards
		suite.accumulateRewards(chainConfig, header, block.Uncles())

		// commit stateDB
		_, err := suite.chain.App.EvmKeeper.CommitStateDB.Commit(chainConfig.IsEIP158(block.Number()))
		suite.Require().NoError(err, "failed to commit StateDB")

		// simulate BaseApp EndBlocker commitment
		suite.chain.CommitBlock()

		// block debugging output
		if block.NumberU64() > 0 && block.NumberU64()%1000 == 0 {
			fmt.Printf("processed block: %d (time so far: %v)\n", block.NumberU64(), time.Since(startTime))
		}
	}
}

// accumulateRewards credits the coinbase of the given block with the mining
// reward. The total reward consists of the static block reward and rewards for
// included uncles. The coinbase of each uncle block is also rewarded.
func (suite *ImporterTestSuite) accumulateRewards(
	config *ethparams.ChainConfig, header *ethtypes.Header, uncles []*ethtypes.Header,
) {

	// select the correct block reward based on chain progression
	blockReward := ethash.FrontierBlockReward
	if config.IsByzantium(header.Number) {
		blockReward = ethash.ByzantiumBlockReward
	}

	// accumulate the rewards for the miner and any included uncles
	reward := new(big.Int).Set(blockReward)
	r := new(big.Int)

	for _, uncle := range uncles {
		r.Add(uncle.Number, rewardBig8)
		r.Sub(r, header.Number)
		r.Mul(r, blockReward)
		r.Div(r, rewardBig8)
		suite.chain.App.EvmKeeper.CommitStateDB.AddBalance(uncle.Coinbase, r)
		r.Div(blockReward, rewardBig32)
		reward.Add(reward, r)
	}

	suite.chain.App.EvmKeeper.CommitStateDB.AddBalance(header.Coinbase, reward)
}

// ApplyDAOHardFork modifies the state database according to the DAO hard-fork
// rules, transferring all balances of a set of DAO accounts to a single refund
// contract.
// Code is pulled from go-ethereum 1.9 because the StateDB interface does not include the
// SetBalance function implementation
// Ref: https://github.com/ethereum/go-ethereum/blob/52f2461774bcb8cdd310f86b4bc501df5b783852/consensus/misc/dao.go#L74
func (suite *ImporterTestSuite) applyDAOHardFork() {
	// Retrieve the contract to refund balances into
	if !suite.chain.App.EvmKeeper.CommitStateDB.Exist(ethparams.DAORefundContract) {
		suite.chain.App.EvmKeeper.CommitStateDB.CreateAccount(ethparams.DAORefundContract)
	}

	// Move every DAO account and extra-balance account funds into the refund contract
	for _, addr := range ethparams.DAODrainList() {
		suite.chain.App.EvmKeeper.CommitStateDB.AddBalance(ethparams.DAORefundContract, suite.chain.App.EvmKeeper.CommitStateDB.GetBalance(addr))
		suite.chain.App.EvmKeeper.CommitStateDB.SetBalance(addr, new(big.Int))
	}
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
// Function is also pulled from go-ethereum 1.9 because of the incompatible usage
// Ref: https://github.com/ethereum/go-ethereum/blob/52f2461774bcb8cdd310f86b4bc501df5b783852/core/state_processor.go#L88
func (suite *ImporterTestSuite) applyTransaction(
	config *ethparams.ChainConfig, bc ethcore.ChainContext, author *ethcmn.Address,
	gp *ethcore.GasPool, header *ethtypes.Header,
	tx *ethtypes.Transaction, usedGas *uint64, cfg ethvm.Config,
) (*ethtypes.Receipt, uint64, error) {
	msg, err := tx.AsMessage(ethtypes.MakeSigner(config, header.Number))
	if err != nil {
		return nil, 0, err
	}

	// Create a new context to be used in the EVM environment
	blockCtx := ethcore.NewEVMBlockContext(header, bc, author)
	txCtx := ethcore.NewEVMTxContext(msg)

	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := ethvm.NewEVM(blockCtx, txCtx, suite.chain.App.EvmKeeper.CommitStateDB, config, cfg)

	// Apply the transaction to the current state (included in the env)
	execResult, err := ethcore.ApplyMessage(vmenv, msg, gp)
	if err != nil {
		// NOTE: ignore vm execution error (eg: tx out of gas at block 51169) as we care only about state transition errors
		return &ethtypes.Receipt{}, 0, nil
	}

	// Update the state with pending changes
	var intRoot ethcmn.Hash
	if config.IsByzantium(header.Number) {
		err = suite.chain.App.EvmKeeper.CommitStateDB.Finalise(true)
	} else {
		intRoot, err = suite.chain.App.EvmKeeper.CommitStateDB.IntermediateRoot(config.IsEIP158(header.Number))
	}

	if err != nil {
		return nil, execResult.UsedGas, err
	}

	root := intRoot.Bytes()
	*usedGas += execResult.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing whether the root touch-delete accounts.
	receipt := ethtypes.NewReceipt(root, execResult.Failed(), *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = execResult.UsedGas

	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = ethcrypto.CreateAddress(vmenv.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs, err = suite.chain.App.EvmKeeper.CommitStateDB.GetLogs(tx.Hash())
	receipt.Bloom = ethtypes.CreateBloom(ethtypes.Receipts{receipt})
	receipt.BlockHash = suite.chain.App.EvmKeeper.CommitStateDB.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(suite.chain.App.EvmKeeper.CommitStateDB.TxIndex())

	return receipt, execResult.UsedGas, err
}
