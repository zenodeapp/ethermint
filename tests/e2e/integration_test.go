package e2e

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/suite"

	"github.com/tharsis/ethermint/testutil/network"
	ethermint "github.com/tharsis/ethermint/types"
)

type IntegrationTestSuite struct {
	suite.Suite

	ctx     context.Context
	cfg     network.Config
	network *network.Network
}

func (s *IntegrationTestSuite) SetupSuite() {
	s.T().Log("setting up integration test suite")

	cfg := network.DefaultConfig()
	cfg.NumValidators = 1

	s.ctx = context.Background()
	s.cfg = cfg
	s.network = network.New(s.T(), cfg)
	s.Require().NotNil(s.network)

	_, err := s.network.WaitForHeight(1)
	s.Require().NoError(err)

	cl, err := ethclient.Dial(s.network.Validators[0].JSONRPCAddress)
	s.Require().NoError(err, "failed to dial JSON-RPC at %s", s.network.Validators[0].JSONRPCAddress)
	s.network.Validators[0].JSONRPCClient = cl
}

func (s *IntegrationTestSuite) TestChainID() {
	chainID, err := s.network.Validators[0].JSONRPCClient.ChainID(s.ctx)
	s.Require().NoError(err)
	s.Require().NotNil(chainID)

	s.T().Log(chainID.Int64())

	eip155ChainID, err := ethermint.ParseChainID(s.network.Config.ChainID)
	s.Require().NoError(err)
	s.Require().Equal(chainID, eip155ChainID)
}

func TestIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}

func (s *IntegrationTestSuite) TestWeb3Sha3() {
	testCases := []struct {
		name     string
		arg      string
		expected string
	}{
		{
			"normal input",
			"0xabcd1234567890",
			"0x23e7488ec9097f0126b0338926bfaeb5264b01cb162a0fd4a6d76e1081c2b24a",
		},
		{
			"0x case",
			"0x",
			"0x39bef1777deb3dfb14f64b9f81ced092c501fee72f90e93d03bb95ee89df9837",
		},
		{
			"empty string case",
			"",
			"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			var result string

			err := s.rpcClient.Call(&result, "web3_sha3", tc.arg)
			s.Require().NoError(err)
			s.Require().Equal(tc.expected, result)
		})
	}
}
