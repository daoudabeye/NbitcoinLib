// See https://aka.ms/new-console-template for more information
using NBitcoin;

namespace IkawariNbitcoinLib
{
    public class Class1
    {
        static void Main(string[] args)
        {
            Network network2 = NBitcoin.Altcoins.Ikawari.Instance.Testnet;
            var genesisBlock = network2.GetGenesis();

            Console.WriteLine(genesisBlock.GetHash()); 
            Console.WriteLine(genesisBlock.Header.GetHash());
            Console.WriteLine(network2.Name);


            Console.WriteLine(new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, network2));
        }
    }

}
