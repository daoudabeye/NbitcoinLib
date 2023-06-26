using NBitcoin;

namespace IkawariNbitcoinLib
{
    public class Class1
    {
        static void Main(string[] args)
        {
            Network network2 = NBitcoin.Altcoins.Ikawari.Instance.Mainnet;

            Console.WriteLine(network2.GenesisHash);

            Console.WriteLine(new Key().PubKey.GetAddress(ScriptPubKeyType.Segwit, network2));
        }
    }

}