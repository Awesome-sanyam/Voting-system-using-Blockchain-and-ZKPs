export default {
  solidity: "0.8.28",
  networks: {
    polygonAmoy: {
      type: "http",
      url: "https://rpc-amoy.polygon.technology/",
      chainId: 80002,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    }
  }
};

