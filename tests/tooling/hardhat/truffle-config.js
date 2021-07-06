module.exports = {
  networks: {
    // Development network is just left as truffle's default settings
    ethermint: {
      host: "127.0.0.1",     // Localhost (default: none)
      port: 8545,            // Standard Ethereum port (default: none)
      network_id: "*",       // Any network (default: none)
      gas: 5000000,          // Gas sent with each transaction
      gasPrice: 1000000000,  // 1 gwei (in wei)
    },
  },
  compilers: {
    solc: {
      version: "0.8.4",    // Fetch exact version from solc-bin (default: truffle's version)
      parser: "solcjs",  // Leverages solc-js purely for speedy parsing
      // docker: true,        // Use "0.5.1" you've installed locally with docker (default: false)
      // settings: {          // See the solidity docs for advice about optimization and evmVersion
      //  optimizer: {
      //    enabled: false,
      //    runs: 200
      //  },
      //  evmVersion: "byzantium"
      // }
    }
  },
}