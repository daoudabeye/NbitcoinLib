using System.Collections.Generic;
using System.Net;
using System;
using System.Reflection;
using NBitcoin.Protocol;
using NBitcoin.Crypto;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using NBitcoin.DataEncoders;
using Ikawari;
using static NBitcoin.Altcoins.XDS;

namespace NBitcoin.Altcoins
{
    /// <summary>
    /// Ikawari is a Proof-of-Work/Proof-of-Stake-v4 coin with SegWit and ColdStaking.
    /// Bitcointalk: https://bitcointalk.org/index.php?topic=5218979.0
    /// </summary>
    public class Ikawari : NetworkSetBase
    {
        public static Ikawari Instance { get; } = new Ikawari();

        public override string CryptoCode => "DCFA";

        public const int MaxReorgLength = 125;

        Ikawari()
        {
        }

        protected override NetworkBuilder CreateMainnet()
        {
            NetworkBuilder builder = new NetworkBuilder();
            CoinSetup setup = IkawariSetup.Instance.Setup;

            var networkName = "IkawariMain";
            var magic = 0x44434641u;
            int defaultPort = 38001;


            builder.SetConsensus(new Consensus
            {
                SubsidyHalvingInterval = 210000, // ok
                MajorityEnforceBlockUpgrade = 750, // ok
                MajorityRejectBlockOutdated = 950, // ok
                MajorityWindow = 1000, // ok
                BIP34Hash = new uint256("0x0000000e13c5bf36c155c7cb1681053d607c191fc44b863d0c5aef6d27b8eb8f"), // ok
                PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")), // ok
                PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60), // ok
                PowTargetSpacing = TimeSpan.FromSeconds(256), // ok
                PowAllowMinDifficultyBlocks = false, // ok
                PowNoRetargeting = false, // ok
                RuleChangeActivationThreshold = 1916, // ?
                MinerConfirmationWindow = 2016, // ok
                CoinType = 1394225, // Genesis nonce
                CoinbaseMaturity = 50, // ok
                ConsensusFactory = IkawariConsensusFactory.FactoryInstance,
                SupportSegwit = true,
                BuriedDeployments = {
                    [BuriedDeployments.BIP34] = 0,
                    [BuriedDeployments.BIP65] = 0,
                    [BuriedDeployments.BIP66] = 0},
                BIP9Deployments =
                {
                    [BIP9Deployments.TestDummy] = new BIP9DeploymentsParameters(28, BIP9DeploymentsParameters.AlwaysActive, 999999999),
                    [BIP9Deployments.CSV] = new BIP9DeploymentsParameters(0, BIP9DeploymentsParameters.AlwaysActive, 999999999),
                    [BIP9Deployments.Segwit] = new BIP9DeploymentsParameters(1, BIP9DeploymentsParameters.AlwaysActive,999999999),
                },
                MinimumChainWork = null
            })
            .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 29 })    // same as Bitcoin but unsupported - bech32/P2WPKH must be used instead
            .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 110 })    // same as Bitcoin but unsupported - bech32/P2WSH must be used instead
            .SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 160 })      // same as Bitcoin
            .SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_NO_EC, new byte[] { 0x01, 0x42 }) // same as Bitcoin
            .SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_EC, new byte[] { 0x01, 0x43 }) // same as Bitcoin
            .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
            .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
            .SetBase58Bytes(Base58Type.PASSPHRASE_CODE, new byte[] { 0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2 })
            .SetBase58Bytes(Base58Type.CONFIRMATION_CODE, new byte[] { 0x64, 0x3B, 0xF6, 0xA8, 0x9A })
            .SetBase58Bytes(Base58Type.ASSET_ID, new byte[] { 23 })
            .SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, "dcfa")
            .SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, "dcfa")
            .SetMagic(magic)
            .SetPort(defaultPort)
            .SetRPCPort(38002)
            .SetName(networkName)
            .SetName("dcfa-main")
            .AddAlias("dcfa-mainnet")
            .AddAlias("ikawari-mainnet")
            .AddAlias("ikawari-main")
            .AddSeeds(new List<NetworkAddress>
            {
                new NetworkAddress(IPAddress.Parse("154.68.23.245"), defaultPort)
            })
            .AddDNSSeeds(new DNSSeedData[0]);

            // Create the genesis block.
            NetworkSetup network = IkawariSetup.Instance.Main;

            var GenesisTime = network.GenesisTime;
            var GenesisNonce = network.GenesisNonce;
            var GenesisBits = network.GenesisBits;
            var GenesisVersion = network.GenesisVersion;
            var GenesisReward = network.GenesisReward;

            Block genesisBlock = CreateGenesisBlock(IkawariConsensusFactory.FactoryInstance,
                GenesisTime,
                GenesisNonce,
                GenesisBits,
                GenesisVersion,
                GenesisReward,
                setup.GenesisText);
            genesisBlock.UpdateMerkleRoot();
            builder.SetGenesis(Encoders.Hex.EncodeData(genesisBlock.ToBytes()));

            /*if (genesisBlock.GetHash() != uint256.Parse("7cea51987e9b1649bf9bc83f62afc20e62bb0d560e85e0aa95e36b67b0f571c2") ||
                genesisBlock.Header.HashMerkleRoot != uint256.Parse("b3bf97881225021122b4c2e374d727ee00252fcf07ad76a3c70ebc3f6951871a"))
				throw new InvalidOperationException($"Invalid network {networkName}.");*/

            return builder;
        }

        protected override NetworkBuilder CreateTestnet()
        {
            NetworkBuilder builder = new NetworkBuilder();

            var networkName = "IkawariTest";
            const int testNetMagicNumberOffset = 1;
            var magic = 0x44434641u + testNetMagicNumberOffset;
            int defaultPort = 35000 + testNetMagicNumberOffset;

            builder.SetConsensus(new Consensus
            {
                SubsidyHalvingInterval = 210000,
                MajorityEnforceBlockUpgrade = 750,
                MajorityRejectBlockOutdated = 950,
                MajorityWindow = 1000,
                BIP34Hash = new uint256("00000d2ff9f3620b5487ed8ec154ce1947fec525e91e6973d1aeae93c53db7a3"),
                PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
                PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
                PowTargetSpacing = TimeSpan.FromSeconds(256),
                PowAllowMinDifficultyBlocks = false,
                PowNoRetargeting = false,
                RuleChangeActivationThreshold = 1916,
                MinerConfirmationWindow = 2016,
                CoinType = 2286,
                CoinbaseMaturity = 50,
                ConsensusFactory = IkawariConsensusFactory.FactoryInstance,
                SupportSegwit = true,
                BuriedDeployments = {
                    [BuriedDeployments.BIP34] = 0,
                    [BuriedDeployments.BIP65] = 0,
                    [BuriedDeployments.BIP66] = 0},
                BIP9Deployments =
                {
                    [BIP9Deployments.TestDummy] = new BIP9DeploymentsParameters(28, BIP9DeploymentsParameters.AlwaysActive, 999999999),
                    [BIP9Deployments.CSV] = new BIP9DeploymentsParameters(0, BIP9DeploymentsParameters.AlwaysActive, 999999999),
                    [BIP9Deployments.Segwit] = new BIP9DeploymentsParameters(1, BIP9DeploymentsParameters.AlwaysActive,999999999),
                },
                MinimumChainWork = null
            })
            .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
            .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
            .SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
            .SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_NO_EC, new byte[] { 0x01, 0x42 })
            .SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_EC, new byte[] { 0x01, 0x43 })
            .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
            .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
            .SetBase58Bytes(Base58Type.PASSPHRASE_CODE, new byte[] { 0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2 })
            .SetBase58Bytes(Base58Type.CONFIRMATION_CODE, new byte[] { 0x64, 0x3B, 0xF6, 0xA8, 0x9A })
            .SetBase58Bytes(Base58Type.ASSET_ID, new byte[] { 23 })
            .SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, "dcfa")
            .SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, "dcfa")
            .SetMagic(magic)
            .SetPort(defaultPort)
            .SetRPCPort(35002)
            .SetName(networkName)
            .SetName("dcfa-test")
            .AddAlias("dcfa-testnet")
            .AddAlias("ikawari-testnet")
            .AddAlias("ikawari-test")
            .AddSeeds(new List<NetworkAddress>())
            .AddDNSSeeds(new DNSSeedData[0]);

            var genesisTime = Utils.DateTimeToUnixTime(new DateTime(2020, 11, 29, 23, 36, 00, DateTimeKind.Utc));
            var genesisNonce = 2286u;
            var genesisBits = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
            var genesisVersion = 1;
            var genesisReward = Money.Zero;

            var genesis = ComputeGenesisBlock(genesisTime, genesisNonce, genesisBits, genesisVersion, genesisReward);
            builder.SetGenesis(Encoders.Hex.EncodeData(genesis.ToBytes()));

            /*if (genesis.GetHash() != uint256.Parse("000b6db2d39e94a2eec38d0d2067e99de541da8874650287d5a19162a716c663") ||
				genesis.Header.HashMerkleRoot != uint256.Parse("8ff8522f0fad24940a5fa24e9ba9b04720b891f6b6fe67b22f9c0e2362ba345b"))
				throw new InvalidOperationException($"Invalid network {networkName}.");*/

            return builder;
        }

        protected override NetworkBuilder CreateRegtest()
        {
            NetworkBuilder builder = new NetworkBuilder();

            var networkName = "IkawariRegTest";
            const int regTestMagicNumberOffset = 2;
            var magic = 0x44434641u + regTestMagicNumberOffset;
            int defaultPort = 25000 + regTestMagicNumberOffset;

            builder.SetConsensus(new Consensus
            {
                SubsidyHalvingInterval = 150,
                MajorityEnforceBlockUpgrade = 750,
                MajorityRejectBlockOutdated = 950,
                MajorityWindow = 1000,
                BIP34Hash = new uint256("00000e48aeeedabface6d45c0de52c7d0edaec14662ab4f56401361f70d12cc6"),
                PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
                PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
                PowTargetSpacing = TimeSpan.FromSeconds(256),
                PowAllowMinDifficultyBlocks = true,
                PowNoRetargeting = true,
                RuleChangeActivationThreshold = 1916,
                MinerConfirmationWindow = 144,
                CoinType = 36463,
                CoinbaseMaturity = 50,
                ConsensusFactory = IkawariConsensusFactory.FactoryInstance,
                SupportSegwit = true,
                BuriedDeployments = {
                    [BuriedDeployments.BIP34] = 0,
                    [BuriedDeployments.BIP65] = 0,
                    [BuriedDeployments.BIP66] = 0},
                BIP9Deployments =
                {
                    [BIP9Deployments.TestDummy] = new BIP9DeploymentsParameters(28, BIP9DeploymentsParameters.AlwaysActive, 999999999),
                    [BIP9Deployments.CSV] = new BIP9DeploymentsParameters(0, BIP9DeploymentsParameters.AlwaysActive, 999999999),
                    [BIP9Deployments.Segwit] = new BIP9DeploymentsParameters(1, BIP9DeploymentsParameters.AlwaysActive,999999999),
                },
                MinimumChainWork = null
            })
            .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
            .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
            .SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
            .SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_NO_EC, new byte[] { 0x01, 0x42 })
            .SetBase58Bytes(Base58Type.ENCRYPTED_SECRET_KEY_EC, new byte[] { 0x01, 0x43 })
            .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
            .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
            .SetBase58Bytes(Base58Type.PASSPHRASE_CODE, new byte[] { 0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2 })
            .SetBase58Bytes(Base58Type.CONFIRMATION_CODE, new byte[] { 0x64, 0x3B, 0xF6, 0xA8, 0x9A })
            .SetBase58Bytes(Base58Type.ASSET_ID, new byte[] { 23 })
            .SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, "dcfa")
            .SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, "dcfa")
            .SetMagic(magic)
            .SetPort(defaultPort)
            .SetRPCPort(25002)
            .SetName(networkName)
            .SetName("dcfa-reg")
            .AddAlias("dcfa-regtest")
            .AddAlias("ikawari-reg")
            .AddAlias("ikawari-regtest")
            .AddSeeds(new List<NetworkAddress>())
            .AddDNSSeeds(new DNSSeedData[0]);

            var genesisTime = Utils.DateTimeToUnixTime(new DateTime(2020, 11, 29, 22, 50, 00, DateTimeKind.Utc));
            var genesisNonce = 36463u;
            var genesisBits = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
            var genesisVersion = 1;
            var genesisReward = Money.Zero;

            var genesis = ComputeGenesisBlock(genesisTime, genesisNonce, genesisBits, genesisVersion, genesisReward);
            builder.SetGenesis(Encoders.Hex.EncodeData(genesis.ToBytes()));


            /*if (genesis.GetHash() != uint256.Parse("00007b1b279769c5bc405dbc895cda71ff6f0e59eee69cdf3ec78c3f4ebb933c") ||
				genesis.Header.HashMerkleRoot != uint256.Parse("32e7cbacc2880bf93cb214ecbf2c36d4c94b77dad1975ba42e50310fc2c43183"))
				throw new InvalidOperationException($"Invalid network {networkName}.");*/

            return builder;
        }

        protected static Block CreateGenesisBlock(ConsensusFactory consensusFactory, 
            uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward, string genesisText)
        {
            Transaction txNew = consensusFactory.CreateTransaction();
            txNew.Version = 1;

            txNew.Inputs.Add(new TxIn()
            {
                ScriptSig = new Script(Op.GetPushOp(0), new Op()
                {
                    Code = (OpcodeType)0x1,
                    PushData = new[] { (byte)42 }
                }, Op.GetPushOp(DataEncoders.Encoders.ASCII.DecodeData(genesisText)))
            });

            txNew.Outputs.Add(new TxOut()
            {
                Value = genesisReward,
            });

            Block genesis = consensusFactory.CreateBlock();
            genesis.Header.BlockTime = Utils.UnixTimeToDateTime(nTime);
            genesis.Header.Bits = nBits;
            genesis.Header.Nonce = nNonce;
            genesis.Header.Version = nVersion;
            genesis.Transactions.Add(txNew);
            genesis.Header.HashPrevBlock = uint256.Zero;
            genesis.UpdateMerkleRoot();

            return genesis;
        }


        public class IkawariConsensusFactory : ConsensusFactory
        {
            IkawariConsensusFactory()
            {
            }

            public static IkawariConsensusFactory FactoryInstance { get; } = new IkawariConsensusFactory();

            public override BlockHeader CreateBlockHeader()
            {
                return new IkawariBlockHeader();
            }

            public override Block CreateBlock()
            {
                return new IkawariBlock(new IkawariBlockHeader());
            }

            public override Transaction CreateTransaction()
            {
                return new Transaction();
            }

            protected bool IsHeadersPayload(Type type)
            {
                var baseType = typeof(HeadersPayload).GetTypeInfo();
                return baseType.IsAssignableFrom(type.GetTypeInfo());
            }

            public override bool TryCreateNew(Type type, out IBitcoinSerializable result)
            {
                if (IsHeadersPayload(type))
                {
                    result = CreateHeadersPayload();
                    return true;
                }

                return base.TryCreateNew(type, out result);
            }

            public HeadersPayload CreateHeadersPayload()
            {
                return new IkawariHeadersPayload();
            }
        }

#pragma warning disable CS0618 // Type or member is obsolete
        public class IkawariBlockHeader : BlockHeader
        {
            public int CurrentVersion => 7;

            public ProvenBlockHeader ProvenBlockHeader { get; set; }

            protected internal override void SetNull()
            {
                nVersion = CurrentVersion;
                hashPrevBlock = 0;
                hashMerkleRoot = 0;
                nTime = 0;
                nBits = 0;
                nNonce = 0;
            }

            protected override HashStreamBase CreateHashStream()
            {
                if (this.Version == 1)
                    return BufferedHashStream.CreateFrom(Sha512T.GetHash);
                return BufferedHashStream.CreateFrom(Hashes.DoubleSHA256RawBytes);
            }

            public override uint256 GetPoWHash()
            {
                var bytes = this.ToBytes();
                return new uint256(Sha512T.GetHash(this.ToBytes(), 0, bytes.Length));
            }
        }
#pragma warning restore CS0618 // Type or member is obsolete

        public class IkawariBlockSignature : IBitcoinSerializable
        {
            protected bool Equals(IkawariBlockSignature other)
            {
                return Equals(signature, other.signature);
            }

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj)) return false;
                if (ReferenceEquals(this, obj)) return true;
                if (obj.GetType() != this.GetType()) return false;
                return Equals((IkawariBlockSignature)obj);
            }

            [SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode")]
            public override int GetHashCode()
            {
                return this.signature != null ? this.signature.Sum(x => (float)x).GetHashCode() : 0;
            }

            public IkawariBlockSignature()
            {
                this.signature = new byte[0];
            }

            private byte[] signature;

            public byte[] Signature
            {
                get => signature;
                set => signature = value;
            }

            public void SetNull()
            {
                signature = new byte[0];
            }

            public bool IsEmpty()
            {
                return !this.signature?.Any() ?? true;
            }

            public static bool operator ==(IkawariBlockSignature a, IkawariBlockSignature b)
            {
                if (ReferenceEquals(a, null))
                {
                    if (ReferenceEquals(b, null))
                    {
                        return true;
                    }

                    return false;
                }
                return a.Equals(b);
            }

            public static bool operator !=(IkawariBlockSignature a, IkawariBlockSignature b)
            {
                return !(a == b);
            }

            #region IBitcoinSerializable Members

            public void ReadWrite(BitcoinStream stream)
            {
                stream.ReadWriteAsVarString(ref signature);
            }

            #endregion

            public override string ToString()
            {
                return this.signature != null ? Encoders.Hex.EncodeData(this.signature) : null;
            }
        }

        public class IkawariBlock : Block
        {
            IkawariBlockSignature blockSignature = new IkawariBlockSignature();

#pragma warning disable CS0618 // Type or member is obsolete
            public IkawariBlock() { }

            public IkawariBlock(BlockHeader blockHeader) : base(blockHeader)
#pragma warning restore CS0618 // Type or member is obsolete
            {
            }

            public override ConsensusFactory GetConsensusFactory()
            {
                return IkawariConsensusFactory.FactoryInstance;
            }

            public IkawariBlockSignature BlockSignature
            {
                get => this.blockSignature;
                set => this.blockSignature = value;
            }

            public override void ReadWrite(BitcoinStream stream)
            {
                base.ReadWrite(stream);
                stream.ReadWrite(ref this.blockSignature);
            }

            public Transaction GetProtocolTransaction()
            {
                return this.Transactions.Count > 1 && IsCoinstake(Transactions[1]) ? this.Transactions[1] : this.Transactions[0];
            }
        }

        public class ProvenBlockHeader : IBitcoinSerializable
        {
            IkawariBlockHeader ikawariBlockHeader;
            Transaction coinstake;
            PartialMerkleTree merkleProof;
            IkawariBlockSignature signature;

            public IkawariBlockHeader IkawariBlockHeader => this.ikawariBlockHeader;
            public Transaction Coinstake => this.coinstake;
            public PartialMerkleTree MerkleProof => this.merkleProof;
            public IkawariBlockSignature Signature => this.signature;

            public long PosHeaderSize { get; protected set; }

            public long MerkleProofSize { get; protected set; }

            public long SignatureSize { get; protected set; }

            public long CoinstakeSize { get; protected set; }

            public long HeaderSize => this.PosHeaderSize + this.MerkleProofSize + this.SignatureSize + this.CoinstakeSize;

            public uint256 StakeModifierV2 { get; set; }

            public ProvenBlockHeader()
            {
            }

            public ProvenBlockHeader(IkawariBlock block, IkawariBlockHeader ikawariBlockHeader)
            {
                if (block == null) throw new ArgumentNullException(nameof(block));

                this.ikawariBlockHeader = ikawariBlockHeader;
                this.ikawariBlockHeader.HashPrevBlock = block.Header.HashPrevBlock;
                this.ikawariBlockHeader.HashMerkleRoot = block.Header.HashMerkleRoot;
                this.ikawariBlockHeader.BlockTime = block.Header.BlockTime;
                this.ikawariBlockHeader.Bits = block.Header.Bits;
                this.ikawariBlockHeader.Nonce = block.Header.Nonce;
                this.ikawariBlockHeader.Version = block.Header.Version;
                this.ikawariBlockHeader.ProvenBlockHeader = this;

                this.signature = block.BlockSignature;
                this.coinstake = block.GetProtocolTransaction();
                this.merkleProof = new MerkleBlock(block, new[] { this.coinstake.GetHash() }).PartialMerkleTree;
            }

            public void ReadWrite(BitcoinStream stream)
            {
                stream.ReadWrite(ref this.ikawariBlockHeader);
                long prev = ProcessedBytes(stream);
                if (!stream.Serializing)
                    this.ikawariBlockHeader.ProvenBlockHeader = this;

                stream.ReadWrite(ref this.merkleProof);
                this.MerkleProofSize = ProcessedBytes(stream) - prev;

                prev = ProcessedBytes(stream);
                stream.ReadWrite(ref this.signature);
                this.SignatureSize = ProcessedBytes(stream) - prev;

                prev = ProcessedBytes(stream);
                stream.ReadWrite(ref this.coinstake);
                this.CoinstakeSize = ProcessedBytes(stream) - prev;
            }

            public override string ToString()
            {
                return this.ikawariBlockHeader.GetHash().ToString();
            }

            public static long ProcessedBytes(BitcoinStream bitcoinStream)
            {
                return bitcoinStream.Serializing ? bitcoinStream.Counter.WrittenBytes : bitcoinStream.Counter.ReadenBytes;
            }
        }

        public class IkawariHeadersPayload : HeadersPayload
        {
            public class BlockHeaderWithTxCount : IBitcoinSerializable
            {
                public BlockHeaderWithTxCount()
                {

                }

                public BlockHeaderWithTxCount(BlockHeader header)
                {
                    Header = header;
                }

                public BlockHeader Header;
                #region IBitcoinSerializable Members

                public void ReadWrite(BitcoinStream stream)
                {
                    stream.ReadWrite(ref Header);
                    VarInt txCount = new VarInt(0);
                    stream.ReadWrite(ref txCount);

                    // Inherited Stratis-specific addition.
                    stream.ReadWrite(ref txCount);
                }

                #endregion
            }

            public override void ReadWriteCore(BitcoinStream stream)
            {
                if (stream.Serializing)
                {
                    var heardersOff = Headers.Select(h => new BlockHeaderWithTxCount(h)).ToList();
                    stream.ReadWrite(ref heardersOff);
                }
                else
                {
                    Headers.Clear();
                    List<BlockHeaderWithTxCount> headersOff = new List<BlockHeaderWithTxCount>();
                    stream.ReadWrite(ref headersOff);
                    Headers.AddRange(headersOff.Select(h => h.Header));
                }
            }
        }

        public static bool IsCoinstake(Transaction transaction)
        {
            return transaction.Inputs.Any()
                   && !transaction.Inputs.First().PrevOut.IsNull
                   && transaction.Outputs.Count == 3
                   && IsEmpty(transaction.Outputs.First());

            bool IsEmpty(TxOut txOut)
            {
                return txOut.Value == Money.Zero && txOut.ScriptPubKey.Length == 0;
            }
        }

        public static class Sha512T
        {
            /// <summary>
            /// Truncated double-SHA512 hash. Used are the first 32 bytes of the second hash output.
            /// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
            /// </summary>
            /// <param name="src">bytes to hash</param>
            /// <returns>hash</returns>
            public static byte[] GetHash(byte[] src, int offset, int count)
            {
                byte[] buffer32 = new byte[32];
                using (var sha512 = SHA512.Create())
                {
                    var buffer64 = sha512.ComputeHash(src, offset, count);
                    buffer64 = sha512.ComputeHash(buffer64);
                    Buffer.BlockCopy(buffer64, 0, buffer32, 0, 32);
                }

                return buffer32;
            }
        }

        static Block ComputeGenesisBlock(uint genesisTime, uint genesisNonce, uint genesisBits, int genesisVersion, Money genesisReward)
        {
            string coinbaseText = "Digital CFA Genesis block";

            Transaction txNew = new Transaction();

            txNew.Version = (uint)1;
            txNew.Inputs.Add(new TxIn
            {
                ScriptSig = new Script(Op.GetPushOp(0L), new Op
                {
                    Code = (OpcodeType)1,
                    PushData = new byte[1] { 42 }
                }, Op.GetPushOp(Encoders.ASCII.DecodeData(coinbaseText)))
            });
            txNew.Outputs.Add(new TxOut
            {
                Value = genesisReward,
            });
            var genesis = IkawariConsensusFactory.FactoryInstance.CreateBlock();
            genesis.Header.BlockTime = Utils.UnixTimeToDateTime(genesisTime);
            genesis.Header.Bits = genesisBits;
            //genesis.Header.Nonce = genesisNonce;
            genesis.Header.Nonce = 0u;
            genesis.Header.Version = genesisVersion;
            genesis.Transactions.Add(txNew);
            genesis.Header.HashPrevBlock = uint256.Zero;
            genesis.UpdateMerkleRoot();

            return genesis;
        }

    }
}
