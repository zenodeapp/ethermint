package network

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	tmcfg "github.com/tendermint/tendermint/config"
	tmflags "github.com/tendermint/tendermint/libs/cli/flags"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/server"
	"github.com/cosmos/cosmos-sdk/server/config"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	srvconfig "github.com/tharsis/ethermint/server/config"
)

type MiniNet struct {
	// T          *testing.T
	BaseDir    string
	Validators []*Validator
}

var miniNetwork *MiniNet = nil

// var startup sync.Once = sync.Once{}
// var cleanup sync.Once = sync.Once{}
var minilock = new(sync.Mutex)

func NewMini() *MiniNet {
	minilock.Lock()
	defer minilock.Unlock()
	if miniNetwork != nil {
		return miniNetwork
	}
	// if miniNetwork == nil {
	// 	startup.Do(func() {
	cfg := DefaultConfig()
	cfg.NumValidators = 1
	baseDir, _ := ioutil.TempDir("/tmp/", cfg.ChainID)
	// require.NoError(t, err)
	// t.Logf("created temporary directory: %s", baseDir)

	// t.Log("preparing test network...")

	var (
		monikers   = make([]string, cfg.NumValidators)
		nodeIDs    = make([]string, cfg.NumValidators)
		valPubKeys = make([]cryptotypes.PubKey, cfg.NumValidators)
	)

	var (
		genAccounts []authtypes.GenesisAccount
		genBalances []banktypes.Balance
		genFiles    []string
	)

	buf := bufio.NewReader(os.Stdin)
	validators := make([]*Validator, cfg.NumValidators)
	// generate private keys, node IDs, and initial transactions
	for i := 0; i < cfg.NumValidators; i++ {
		appCfg := srvconfig.DefaultConfig()
		appCfg.Pruning = cfg.PruningStrategy
		appCfg.MinGasPrices = cfg.MinGasPrices
		appCfg.API.Enable = true
		appCfg.API.Swagger = false
		appCfg.Telemetry.Enabled = false

		ctx := server.NewDefaultContext()

		tmCfg := ctx.Config
		tmCfg.Consensus.TimeoutCommit = cfg.TimeoutCommit

		// Only allow the first validator to expose an RPC, API and gRPC
		// server/client due to Tendermint in-process constraints.
		apiAddr := ""
		jsonRPCAddr := ""
		tmCfg.RPC.ListenAddress = ""
		appCfg.GRPC.Enable = false
		appCfg.JSONRPC.Enable = false

		if i == 0 {
			apiListenAddr, _, err := server.FreeTCPAddr()
			// require.NoError(t, err)
			appCfg.API.Address = apiListenAddr

			apiURL, err := url.Parse(apiListenAddr)
			// require.NoError(t, err)
			apiAddr = fmt.Sprintf("http://%s:%s", apiURL.Hostname(), apiURL.Port())

			jsonRPCListenAddr, _, err := server.FreeTCPAddr()
			fmt.Printf("e: %v %v", err, jsonRPCListenAddr)

			// require.NoError(t, err)
			// t.Log(jsonRPCListenAddr)
			appCfg.JSONRPC.Address = jsonRPCListenAddr
			appCfg.JSONRPC.Enable = true

			jsonRPCAPIURL, err := url.Parse(jsonRPCListenAddr)
			// require.NoError(t, err)
			jsonRPCAddr = fmt.Sprintf("http://%s:%s", jsonRPCAPIURL.Hostname(), jsonRPCAPIURL.Port())

			rpcAddr, _, err := server.FreeTCPAddr()
			// require.NoError(t, err)
			tmCfg.RPC.ListenAddress = rpcAddr
			// t.Log(rpcAddr)

			_, grpcPort, err := server.FreeTCPAddr()
			// require.NoError(t, err)
			appCfg.GRPC.Address = fmt.Sprintf("0.0.0.0:%s", grpcPort)
			appCfg.GRPC.Enable = true
		}

		logger := log.NewNopLogger()
		if cfg.EnableLogging {
			logger = log.NewTMLogger(log.NewSyncWriter(os.Stdout))
			logger, _ = tmflags.ParseLogLevel("info", logger, tmcfg.DefaultLogLevel)
		}

		ctx.Logger = logger

		nodeDirName := fmt.Sprintf("node%d", i)
		nodeDir := filepath.Join(baseDir, nodeDirName, "ethermintd")
		gentxsDir := filepath.Join(baseDir, "gentxs")
		os.MkdirAll(filepath.Join(nodeDir, "config"), 0o755)
		// require.NoError(t, os.MkdirAll(filepath.Join(nodeDir, "config"), 0o755))

		tmCfg.SetRoot(nodeDir)
		tmCfg.Moniker = nodeDirName
		monikers[i] = nodeDirName

		proxyAddr, _, err := server.FreeTCPAddr()
		// require.NoError(t, err)
		tmCfg.ProxyApp = proxyAddr

		p2pAddr, _, err := server.FreeTCPAddr()
		// require.NoError(t, err)
		tmCfg.P2P.ListenAddress = p2pAddr
		tmCfg.P2P.AddrBookStrict = false
		tmCfg.P2P.AllowDuplicateIP = true

		nodeID, pubKey, err := genutil.InitializeNodeValidatorFiles(tmCfg)
		// require.NoError(t, err)
		nodeIDs[i] = nodeID
		valPubKeys[i] = pubKey

		kb, err := keyring.New(sdk.KeyringServiceName(), keyring.BackendTest, nodeDir, buf, cfg.KeyringOptions...)
		// require.NoError(t, err)

		keyringAlgos, _ := kb.SupportedAlgorithms()
		algo, err := keyring.NewSigningAlgoFromString(cfg.SigningAlgo, keyringAlgos)
		// require.NoError(t, err)

		addr, secret, err := server.GenerateSaveCoinKey(kb, nodeDirName, true, algo)
		// require.NoError(t, err)

		info := map[string]string{"secret": secret}
		infoBz, err := json.Marshal(info)
		// require.NoError(t, err)

		// save private key seed words
		writeFile(fmt.Sprintf("%v.json", "key_seed"), nodeDir, infoBz)
		// require.NoError(t, writeFile(fmt.Sprintf("%v.json", "key_seed"), nodeDir, infoBz))

		balances := sdk.NewCoins(
			sdk.NewCoin(fmt.Sprintf("%stoken", nodeDirName), cfg.AccountTokens),
			sdk.NewCoin(cfg.BondDenom, cfg.StakingTokens),
		)

		genFiles = append(genFiles, tmCfg.GenesisFile())
		genBalances = append(genBalances, banktypes.Balance{Address: addr.String(), Coins: balances.Sort()})
		genAccounts = append(genAccounts, authtypes.NewBaseAccount(addr, nil, 0, 0))

		commission, err := sdk.NewDecFromStr("0.5")
		// require.NoError(t, err)

		createValMsg, err := stakingtypes.NewMsgCreateValidator(
			sdk.ValAddress(addr),
			valPubKeys[i],
			sdk.NewCoin(cfg.BondDenom, cfg.BondedTokens),
			stakingtypes.NewDescription(nodeDirName, "", "", "", ""),
			stakingtypes.NewCommissionRates(commission, sdk.OneDec(), sdk.OneDec()),
			sdk.OneInt(),
		)
		// require.NoError(t, err)

		p2pURL, err := url.Parse(p2pAddr)
		// require.NoError(t, err)

		memo := fmt.Sprintf("%s@%s:%s", nodeIDs[i], p2pURL.Hostname(), p2pURL.Port())
		fee := sdk.NewCoins(sdk.NewCoin(fmt.Sprintf("%stoken", nodeDirName), sdk.NewInt(0)))
		txBuilder := cfg.TxConfig.NewTxBuilder()
		txBuilder.SetMsgs(createValMsg)
		// require.NoError(t, txBuilder.SetMsgs(createValMsg))
		txBuilder.SetFeeAmount(fee)    // Arbitrary fee
		txBuilder.SetGasLimit(1000000) // Need at least 100386
		txBuilder.SetMemo(memo)

		txFactory := tx.Factory{}
		txFactory = txFactory.
			WithChainID(cfg.ChainID).
			WithMemo(memo).
			WithKeybase(kb).
			WithTxConfig(cfg.TxConfig)

		err = tx.Sign(txFactory, nodeDirName, txBuilder, true)
		// require.NoError(t, err)

		txBz, err := cfg.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
		writeFile(fmt.Sprintf("%v.json", nodeDirName), gentxsDir, txBz)
		// require.NoError(t, err)
		// require.NoError(t, writeFile(fmt.Sprintf("%v.json", nodeDirName), gentxsDir, txBz))

		config.WriteConfigFile(filepath.Join(nodeDir, "config/app.toml"), appCfg)
		ctx.Viper.AddConfigPath(fmt.Sprintf("%s/config", nodeDir))
		ctx.Viper.SetConfigName("app")
		ctx.Viper.SetConfigType("toml")
		err = ctx.Viper.ReadInConfig()
		if err != nil {
			panic(err)
		}

		clientCtx := client.Context{}.
			WithKeyringDir(nodeDir).
			WithKeyring(kb).
			WithHomeDir(tmCfg.RootDir).
			WithChainID(cfg.ChainID).
			WithInterfaceRegistry(cfg.InterfaceRegistry).
			WithCodec(cfg.Codec).
			WithLegacyAmino(cfg.LegacyAmino).
			WithTxConfig(cfg.TxConfig).
			WithAccountRetriever(cfg.AccountRetriever)

		validators[i] = &Validator{
			AppConfig:       appCfg,
			ClientCtx:       clientCtx,
			Ctx:             ctx,
			Dir:             filepath.Join(baseDir, nodeDirName),
			NodeID:          nodeID,
			PubKey:          pubKey,
			Moniker:         nodeDirName,
			RPCAddress:      tmCfg.RPC.ListenAddress,
			P2PAddress:      tmCfg.P2P.ListenAddress,
			APIAddress:      apiAddr,
			JSONRPCAddress:  jsonRPCAddr,
			EthereumAddress: common.BytesToAddress(addr),
			Address:         addr,
			ValAddress:      sdk.ValAddress(addr),
		}
	}
	initGenFiles(cfg, genAccounts, genBalances, genFiles)
	collectGenFiles(cfg, validators, baseDir)
	// require.NoError(t, initGenFiles(cfg, genAccounts, genBalances, genFiles))
	// require.NoError(t, collectGenFiles(cfg, validators, baseDir))

	// t.Log("starting test network...")
	for _, v := range validators {
		startInProcess(cfg, v)
		// require.NoError(t, startInProcess(cfg, v))
	}

	// t.Log("started test network")
	miniNetwork = &MiniNet{
		// T:          t,
		Validators: validators,
		BaseDir:    baseDir,
	}

	// Ensure we cleanup incase any test was abruptly halted (e.g. SIGINT) as any
	// defer in a test would not be called.
	server.TrapSignal(miniNetwork.Cleanup)

	// })
	// }
	return miniNetwork
}

// LatestHeight returns the latest height of the network or an error if the
// query fails or no validators exist.
func (n *MiniNet) LatestHeight() (int64, error) {
	if len(n.Validators) == 0 {
		return 0, errors.New("no validators available")
	}

	status, err := n.Validators[0].RPCClient.Status(context.Background())
	if err != nil {
		return 0, err
	}

	return status.SyncInfo.LatestBlockHeight, nil
}

// WaitForHeight performs a blocking check where it waits for a block to be
// committed after a given block. If that height is not reached within a timeout,
// an error is returned. Regardless, the latest height queried is returned.
func (n *MiniNet) WaitForHeight(h int64) (int64, error) {
	return n.WaitForHeightWithTimeout(h, 10*time.Second)
}

// WaitForHeightWithTimeout is the same as WaitForHeight except the caller can
// provide a custom timeout.
func (n *MiniNet) WaitForHeightWithTimeout(h int64, t time.Duration) (int64, error) {
	ticker := time.NewTicker(time.Second)
	timeout := time.After(t)

	if len(n.Validators) == 0 {
		return 0, errors.New("no validators available")
	}

	var latestHeight int64
	val := n.Validators[0]

	for {
		select {
		case <-timeout:
			ticker.Stop()
			return latestHeight, errors.New("timeout exceeded waiting for block")
		case <-ticker.C:
			status, err := val.RPCClient.Status(context.Background())
			if err == nil && status != nil {
				latestHeight = status.SyncInfo.LatestBlockHeight
				if latestHeight >= h {
					return latestHeight, nil
				}
			}
		}
	}
}

// WaitForNextBlock waits for the next block to be committed, returning an error
// upon failure.
func (n *MiniNet) WaitForNextBlock() error {
	lastBlock, err := n.LatestHeight()
	if err != nil {
		return err
	}

	_, err = n.WaitForHeight(lastBlock + 1)
	if err != nil {
		return err
	}

	return err
}

// Cleanup removes the root testing (temporary) directory and stops both the
// Tendermint and API services. It allows other callers to create and start
// test networks. This method must be called when a test is finished, typically
// in a defer.
func (n *MiniNet) Cleanup() {
	minilock.Lock()
	defer minilock.Unlock()
	// cleanup.Do(func() {
	// n.T.Log("cleaning up test network...")

	for _, v := range n.Validators {
		if v.tmNode != nil && v.tmNode.IsRunning() {
			_ = v.tmNode.Stop()
		}

		if v.api != nil {
			_ = v.api.Close()
		}

		if v.grpc != nil {
			v.grpc.Stop()
		}

		if v.jsonRPC != nil {
			v.jsonRPC.Stop()
		}
	}
	_ = os.RemoveAll(n.BaseDir)

	// n.T.Log("finished cleaning up test network")
	// })

}
