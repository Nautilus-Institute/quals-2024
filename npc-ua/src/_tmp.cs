// See https://aka.ms/new-console-template for more information
//Console.WriteLine("Hello, World! {0}", "".GetHashCode());
using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;


class DeterministicECDSA : IDsaKCalculator {
    private readonly HMac hMac;
    
    public readonly byte[] K;
    public readonly byte[] V;
    private BigInteger n;

    public DeterministicECDSA(IDigest digest, String message) {
        this.hMac = new HMac(digest);
        Console.WriteLine("In constructor for DeterministicECDSA");
        this.V = new byte[hMac.GetMacSize()];
        this.K = new byte[hMac.GetMacSize()];
        this.n = BigInteger.Zero;
        uint hc = (uint)message.GetHashCode();
        Console.WriteLine("hc: {0}", hc);
        byte[] v_v = BitConverter.GetBytes(hc);
        Buffer.BlockCopy(v_v, 0, this.V, 0, v_v.Length);
        Console.WriteLine("V after init: {0}", Convert.ToHexString(v_v));
    }

    public virtual void Init(BigInteger n, SecureRandom random)
    {
        throw new InvalidOperationException("Operation not supported");
    }

    public virtual bool IsDeterministic
    {
        get { return true; }
    }

    public void Init(BigInteger n, BigInteger d, byte[] message) {
        Console.WriteLine("In DeterministicECDSA.Init");

        this.n = n;
        byte[] v_v = BitConverter.GetBytes((uint)d.GetHashCode());
        Buffer.BlockCopy(v_v,0, this.K, 0, v_v.Length);

        //Arrays.Fill(V, 0x01);
        //Arrays.Fill(K, 0);

        //base.Init(n, d, message);
        Console.WriteLine("K after init: {0}", Convert.ToHexString(this.K));
        Console.WriteLine("V after init: {0}", Convert.ToHexString(this.V));
        
        //this.K = new byte[hMac.GetMacSize()];
        //this.V = new byte[hMac.GetMacSize()];
        //d.GetHashCode() ^ 
    }

    public virtual BigInteger NextK() {
        byte[] t = new byte[BigIntegers.GetUnsignedByteLength(n)];
        for (;;) {
            int tOff = 0;
            while (tOff < t.Length)
            {
                hMac.BlockUpdate(V, 0, V.Length);
                hMac.DoFinal(V, 0);

                int len = System.Math.Min(t.Length - tOff, V.Length);
                Array.Copy(V, 0, t, tOff, len);
                tOff += len;
            }
            BigInteger k = BitsToInt(t);
            if (k.SignValue > 0 && k.CompareTo(n) < 0) {
                Console.WriteLine("Chosen K: {0}", k.ToString(16));
                return k;
            }
            hMac.BlockUpdate(V, 0, V.Length);
            hMac.Update(0x00);
            hMac.DoFinal(K, 0);
            hMac.Init(new KeyParameter(K));
            hMac.BlockUpdate(V, 0, V.Length);
            hMac.DoFinal(V, 0);
        }

    }

    private BigInteger BitsToInt(byte[] t) {
        BigInteger bigInteger = new BigInteger(1, t);
        if (t.Length * 8 > this.n.BitLength)
        {
            bigInteger = bigInteger.ShiftRight(t.Length * 8 - this.n.BitLength);
        }
        return bigInteger;
    }
}


class TestClass {

    static byte[] ToByteArray(String hexString)
    {
      byte[] retval = new byte[hexString.Length / 2];
      for (int i = 0; i < hexString.Length; i += 2)
        retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
      return retval;
    }

    static String SignData(AsymmetricCipherKeyPair keyPair, String data) {
        ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters)keyPair.Private;
        //ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters)keyPair.Public;

        var c = new DeterministicECDSA(new Sha256Digest(), data);
        byte[] data_bytes = Encoding.Unicode.GetBytes(data);
        Console.WriteLine("Signing data: {0}", data);

        SHA256 sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(data_bytes);
        Console.WriteLine("hash: {0}", BitConverter.ToString(hash));

        var s = new ECDsaSigner(c);
        s.Init(true, privateKeyParams);

        BigInteger [] rs = s.GenerateSignature(hash);
        Console.WriteLine("R: {0}", rs[0].ToString(16));
        Console.WriteLine("S: {0}", rs[1].ToString(16));

        using var bos = new MemoryStream(72);
        using (var seq = new DerSequenceGenerator(bos))
        {
            seq.AddObject(new DerInteger(rs[0]));
            seq.AddObject(new DerInteger(rs[1]));
        }

        byte[] sig = bos.ToArray();
        //var sig_s = BitConverter.ToString(sig);
        var sig_s = System.Convert.ToBase64String(sig);
        Console.WriteLine("Sig: {0}", sig_s);
        return sig_s;
    }
    static bool VerifyData(AsymmetricCipherKeyPair keyPair, String data, String sig_s) {
        Console.WriteLine("Verifying data: `{0}` with sig `{1}`", data, sig_s);
        ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters)keyPair.Public;

        var sig = System.Convert.FromBase64String(sig_s);
        Asn1Sequence asn1Sequence = (Asn1Sequence)Asn1Object.FromByteArray(sig);
        var rs = new[]
        {
            ((DerInteger)asn1Sequence[0]).Value,
            ((DerInteger)asn1Sequence[1]).Value,
        };

        var verifier = new ECDsaSigner();
        verifier.Init(false, publicKeyParams);

        byte[] data_bytes = Encoding.Unicode.GetBytes(data);
        SHA256 sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(data_bytes);
        Console.WriteLine("hash: {0}", BitConverter.ToString(hash));

        Console.WriteLine("Rver: {0}", rs[0].ToString(16));
        Console.WriteLine("Sver: {0}", rs[1].ToString(16));

        bool res =  verifier.VerifySignature(hash, rs[0], rs[1]);
        Console.WriteLine("Valid: {0}", res);
        return res;
    }
    public static void Main() {
        byte[] utf16Data = new byte[8];

        utf16Data[0] = 0x22;
        utf16Data[1] = 0x00;
        utf16Data[2] = 0x43;
        utf16Data[3] = 0x44;
        utf16Data[4] = 0x45;
        utf16Data[5] = 0x46;
        utf16Data[6] = 0x47;
        utf16Data[7] = 0x48;

        /*
        Random rnd = new Random();

        for (uint i =0;i<10; i++) {
            utf16Data[0] = (byte)i;
            //rnd.NextBytes(utf16Data);
            string hexString = BitConverter.ToString(utf16Data);
            var t = Encoding.Unicode.GetString(utf16Data);

            Console.WriteLine("{0}:{1}", hexString, (uint)t.GetHashCode());
        }
        */

        //Console.InputEncoding = Encoding.Unicode;

        Assembly assembly = Assembly.Load("System.Private.CoreLib");
        //Console.WriteLine("Assembly: {0}", assembly);

        Type? type = assembly.GetType("System.Marvin", false, false);
        //Console.WriteLine("Marvin: {0}", type);
        if (type != null) {
        PropertyInfo? info = type.GetProperty("DefaultSeed");
        //Console.WriteLine("DefaultSeed: {0}", info);
        if (info != null) {
            object? val = info.GetValue(null, null);
            Console.WriteLine("Seed: {0}", val);
        }
        }

        string pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIOpBk1tAVWUOObdhwWYusVUnYSwJpDdUCcS7dn1Y5CBQoAcGBSuBBAAK\noUQDQgAEiydvGXZlAdA0lCM/cvwwcOQw+B6Ez1VKurkYVsXPY5kMUJQ65ujRM2iV\nVNaJj8770cjd4BJrkYf5zcY+xkkiwg==\n-----END EC PRIVATE KEY-----";

        PemReader pr = new PemReader(new StringReader(pem));
        AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();

        string hexString = BitConverter.ToString(utf16Data);
        var t = Encoding.Unicode.GetString(utf16Data);
        Console.WriteLine("{0}:{1}", hexString, (uint)t.GetHashCode());
        String sig1 = SignData(keyPair, t);
        VerifyData(keyPair, t, sig1);

        Console.WriteLine("Send hex:\n");
        string? line = Console.ReadLine();
        if (line != null) {
            byte[] new_data = ToByteArray(line);
            var t2 = Encoding.Unicode.GetString(new_data);
            hexString = BitConverter.ToString(new_data);
            Console.WriteLine("{0}:{1}", hexString, (uint)t2.GetHashCode());
            String sig2 = SignData(keyPair, t2);
            VerifyData(keyPair, t2, sig2);
        }

        Console.WriteLine("Send signed data:\n");
        line = Console.ReadLine();
        if (line != null) {
            string t3 = line;
            Console.WriteLine("Send sig:\n");
            string? sig3 = Console.ReadLine();
            if (sig3 != null) {
                VerifyData(keyPair, t3, sig3);
            }
        }




//var t = Encoding.Unicode.GetString(utf16Data);
//Console.WriteLine("Hello, World! {0}", t.GetHashCode());

//Encoding.Unicode.GetBytes(myText)

    }
}
