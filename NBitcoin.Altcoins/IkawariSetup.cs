using NBitcoin;
using System;
using System.Collections.Generic;
namespace Ikawari
{
    internal class CoinSetup
    {
        internal string FileNamePrefix;
        internal string ConfigFileName;
        internal string Magic;
        internal int CoinType;
        internal decimal PremineReward;
        internal decimal PoWBlockReward;
        internal decimal PoSBlockReward;
        internal int LastPowBlock;
        internal string GenesisText;
        internal TimeSpan TargetSpacing;
        internal uint ProofOfStakeTimestampMask;
        internal int PoSVersion;
    }

    internal class NetworkSetup
    {
        internal string Name;
        internal string RootFolderName;
        internal string CoinTicker;
        internal int DefaultPort;
        internal int DefaultRPCPort;
        internal int DefaultAPIPort;
        internal int PubKeyAddress;
        internal int ScriptAddress;
        internal int SecretAddress;
        internal uint GenesisTime;
        internal uint GenesisNonce;
        internal uint GenesisBits;
        internal int GenesisVersion;
        internal Money GenesisReward;
        internal string HashGenesisBlock;
        internal string HashMerkleRoot;
        internal string[] DNS;
        internal string[] Nodes;
    }
    internal class IkawariSetup
   {
      internal static IkawariSetup Instance = new IkawariSetup();

      internal CoinSetup Setup = new CoinSetup
      {
          FileNamePrefix = "ikawari",
          ConfigFileName = "ikawari.conf",
          Magic = "44-43-46-41",
          CoinType = 3601, // SLIP-0044: https://github.com/satoshilabs/slips/blob/master/slip-0044.md,
          PremineReward = 10000000,
          PoWBlockReward = 10,
          PoSBlockReward = 10,
          LastPowBlock = 25000,
          GenesisText = "Digital CFA Genesis block", // The New York Times, 2020-04-16
          TargetSpacing = TimeSpan.FromSeconds(64),
          ProofOfStakeTimestampMask = 0x0000000F, // 0x0000003F // 64 sec
          PoSVersion = 3
      };

      internal NetworkSetup Main = new NetworkSetup
      {
          Name = "ikawariMain",
          RootFolderName = "ikawari",
          CoinTicker = "DCFA",
          DefaultPort = 38001,
          DefaultRPCPort = 38002,
          DefaultAPIPort = 38003,
          PubKeyAddress = 29, // B https://en.bitcoin.it/wiki/List_of_address_prefixes
          ScriptAddress = 135, // b
          SecretAddress = 16,
          GenesisTime = 1687815284,
          GenesisNonce = 102772,
          GenesisBits = 0x1E0FFFFF,
          GenesisVersion = 1,
          GenesisReward = Money.Zero,
          HashGenesisBlock = "00000a9ebbe4ac48777a60b7cca4885a9969d58470c91f09614442b919ff1392",
          HashMerkleRoot = "b3bf97881225021122b4c2e374d727ee00252fcf07ad76a3c70ebc3f6951871a",
          DNS = new[] { "seed.ikanet.org", "seed.ikanet.ml", "dcfa.seed.blockcore.net" },
          Nodes = new[] { "154.68.23.243", "154.68.23.245" },
      };

      internal NetworkSetup RegTest = new NetworkSetup
      {
          Name = "ikawariRegTest",
          RootFolderName = "ikawariregtest",
          CoinTicker = "TDCFA",
          DefaultPort = 25001,
          DefaultRPCPort = 25002,
          DefaultAPIPort = 25003,
          PubKeyAddress = 111,
          ScriptAddress = 196,
          SecretAddress = 239,
          GenesisTime = 1687815292,
          GenesisNonce = 120366,
          GenesisBits = 0x1F00FFFF,
          GenesisVersion = 1,
          GenesisReward = Money.Zero,
          HashGenesisBlock = "000045c3b4efa8c130b9f20e34fc37e7af9947d7f00e15b316ab3b23e53cd93f",
          HashMerkleRoot = "b3bf97881225021122b4c2e374d727ee00252fcf07ad76a3c70ebc3f6951871a",
          DNS = new[] { "seedregtest1.dcfa.blockcore.net", "seedregtest2.dcfa.blockcore.net", "seedregtest.dcfa.blockcore.net" },
          Nodes = new[] { "154.68.23.243", "154.68.23.245" },
      };

      internal NetworkSetup Test = new NetworkSetup
      {
          Name = "ikawariTest",
          RootFolderName = "ikawaritest",
          CoinTicker = "TDCFA",
          DefaultPort = 35001,
          DefaultRPCPort = 35002,
          DefaultAPIPort = 35003,
          PubKeyAddress = 111,
          ScriptAddress = 196,
          SecretAddress = 239,
          GenesisTime = 1687815300,
          GenesisNonce = 10982,
          GenesisBits = 0x1F0FFFFF,
          GenesisVersion = 1,
          GenesisReward = Money.Zero,
          HashGenesisBlock = "0005656e0cbb58b891e14a5d559501cc56cf6b82a660b9ad16fd50c75d86e819",
          HashMerkleRoot = "b3bf97881225021122b4c2e374d727ee00252fcf07ad76a3c70ebc3f6951871a",
          DNS = new[] { "seedtest1.dcfa.blockcore.net", "seedtest2.dcfa.blockcore.net", "seedtest.dcfa.blockcore.net" },
          Nodes = new[] { "154.68.23.243", "154.68.23.245" },
      };

      public bool IsPoSv3()
      {
         return Setup.PoSVersion == 3;
      }

      public bool IsPoSv4()
      {
         return Setup.PoSVersion == 4;
      }
   }
}
