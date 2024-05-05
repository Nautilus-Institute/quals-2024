namespace crypto.nautilus;

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

    public DeterministicECDSA(IDigest digest, uint HashCode) {
        this.hMac = new HMac(digest);
        //Console.WriteLine("In constructor for DeterministicECDSA");
        this.V = new byte[hMac.GetMacSize()];
        this.K = new byte[hMac.GetMacSize()];
        this.n = BigInteger.Zero;
        uint hc = (uint)HashCode;
        //Console.WriteLine("hc: {0}", hc);
        byte[] v_v = BitConverter.GetBytes(hc);
        Buffer.BlockCopy(v_v, 0, this.V, 0, v_v.Length);
        //Console.WriteLine("V after init: {0}", Convert.ToHexString(v_v));
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
        //Console.WriteLine("In DeterministicECDSA.Init");

        this.n = n;
        byte[] v_v = BitConverter.GetBytes((uint)d.GetHashCode());
        Buffer.BlockCopy(v_v,0, this.K, 0, v_v.Length);

        //Arrays.Fill(V, 0x01);
        //Arrays.Fill(K, 0);

        //base.Init(n, d, message);
        //Console.WriteLine("K after init: {0}", Convert.ToHexString(this.K));
        //Console.WriteLine("V after init: {0}", Convert.ToHexString(this.V));
        
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
                //Console.WriteLine("Chosen K: {0}", k.ToString(16));
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

public class Crypto
{
    // Constructor
    AsymmetricCipherKeyPair keyPair;

    public Crypto(String file_path) {

        String pem = File.ReadAllText(file_path);
        PemReader pr = new PemReader(new StringReader(pem));
        this.keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();

        //Console.WriteLine("In Crypto constructor");
    }

    public String SignString(String data) {

        var hashcode = (uint)data.GetHashCode();

        // Read contents from file
        ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters)this.keyPair.Private;
        //ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters)keyPair.Public;

        var c = new DeterministicECDSA(new Sha256Digest(), hashcode);
        byte[] data_bytes = Encoding.Unicode.GetBytes(data);
        //Console.WriteLine("Signing data: {0}", data);

        SHA256 sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(data_bytes);
        //Console.WriteLine("hash: {0}", BitConverter.ToString(hash));

        var s = new ECDsaSigner(c);
        s.Init(true, privateKeyParams);

        BigInteger [] rs = s.GenerateSignature(hash);
        //Console.WriteLine("R: {0}", rs[0].ToString(16));
        //Console.WriteLine("S: {0}", rs[1].ToString(16));

        /*
        string r_s = System.Convert.ToBase64String(rs[0].ToByteArray());
        string s_s = System.Convert.ToBase64String(rs[1].ToByteArray());
        string sig_s = r_s + "." + s_s;
        */

        using var bos = new MemoryStream(72);
        using (var seq = new DerSequenceGenerator(bos))
        {
            seq.AddObject(new DerInteger(rs[0]));
            seq.AddObject(new DerInteger(rs[1]));
        }

        byte[] sig = bos.ToArray();
        //var sig_s = BitConverter.ToString(sig);
        var sig_s = System.Convert.ToBase64String(sig);
        //Console.WriteLine("Sig: {0}", sig_s);
        return sig_s;
    }

    public bool VerifyString(String data, String sig_s) {
        //Console.WriteLine("Verifying data: `{0}` with sig `{1}`", data, sig_s);
        ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters)this.keyPair.Public;

        /*
        // Split on period
        string[] parts = sig_s.Split('.');
        if (parts.Length != 2)
        {
            return false;
        }
        BigInteger r = new BigInteger(System.Convert.FromBase64String(parts[0]));
        BigInteger s = new BigInteger(System.Convert.FromBase64String(parts[1]));
        */

        // Convert from hex to bigint
        //BigInteger r = new BigInteger(parts[0], 16);
        //BigInteger s = new BigInteger(parts[1], 16);

        var sig = System.Convert.FromBase64String(sig_s);
        Asn1Sequence asn1Sequence = (Asn1Sequence)Asn1Object.FromByteArray(sig);
        var rs = new[]
        {
            ((DerInteger)asn1Sequence[0]).Value,
            ((DerInteger)asn1Sequence[1]).Value,
        };

        BigInteger r = rs[0];
        BigInteger s = rs[1];

        var verifier = new ECDsaSigner();
        verifier.Init(false, publicKeyParams);

        byte[] data_bytes = Encoding.Unicode.GetBytes(data);
        SHA256 sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(data_bytes);
        //Console.WriteLine("hash: {0}", BitConverter.ToString(hash));

        //Console.WriteLine("Rver: {0}", r);
        //Console.WriteLine("Sver: {0}", s);

        bool res =  verifier.VerifySignature(hash, r, s);
        //Console.WriteLine("Valid: {0}", res);
        return res;
    }
}
