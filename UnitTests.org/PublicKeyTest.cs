using System;
using System.Diagnostics;
using JosePCL.Keys.Rsa;
using JosePCL.Util;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using PCLCrypto;

namespace UnitTests
{
    [TestClass]
    public class PublicKeyTest
    {
        private const string Pkcs1 = @"MIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmStuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI2QIDAQAB";
        private const string X509Pki = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmStuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI2QIDAQAB";

        private const string PemPubKey =
@"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
2QIDAQAB
-----END PUBLIC KEY-----";

        private const string PemRsaPubKey =
@"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
2QIDAQAB
-----END RSA PUBLIC KEY-----";

        [TestMethod]
        public void LoadPubKeyPemEncoded()
        {          
            //when
            var test = PublicKey.Load(PemPubKey);
            var roundtrip = Convert.ToBase64String(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey));

            //then
            Assert.AreEqual(2048,test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }

        [TestMethod]
        public void LoadRsaPubKeyPemEncoded()
        {
            //when
            var test = PublicKey.Load(PemRsaPubKey);
            var roundtrip = Convert.ToBase64String(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey));

            //then
            Assert.AreEqual(2048, test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }

        [TestMethod]
        public void LoadPubKeyRaw()
        {
            //when
            var test = PublicKey.Load(Pkcs1);
            var roundtrip = Convert.ToBase64String(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey));
            //then
            Assert.AreEqual(2048, test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }

        [TestMethod]
        public void LoadRsaPubKeyRaw()
        {
            //when
            var test = PublicKey.Load(X509Pki);
            var roundtrip=Convert.ToBase64String(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey));

            //then
            Assert.AreEqual(2048, test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }
        
        [TestMethod]
        public void NewRsaPubKeyRaw()
        {
            //when
            var e = new byte[] {1, 0, 1};
            var n = new byte[] { 0, 168, 86, 111, 210, 151, 154, 254, 57, 249, 50, 142, 42, 17, 73, 146, 182, 232, 101, 186, 91, 40, 242, 125, 98, 157, 118, 196, 162, 215, 127, 205, 58, 208, 167, 210, 180, 68, 173, 33, 127, 187, 116, 43, 128, 99, 41, 88, 90, 138, 162, 26, 155, 139, 85, 85, 11, 228, 153, 135, 129, 121, 138, 245, 50, 105, 206, 255, 67, 125, 237, 211, 1, 207, 254, 223, 154, 252, 175, 210, 24, 7, 104, 23, 80, 230, 100, 121, 187, 114, 211, 148, 122, 60, 182, 52, 68, 239, 225, 179, 102, 97, 172, 234, 51, 28, 202, 62, 199, 109, 122, 27, 12, 244, 9, 102, 154, 141, 203, 162, 99, 150, 32, 213, 95, 21, 188, 157, 98, 67, 122, 220, 70, 6, 90, 166, 78, 61, 68, 213, 250, 246, 68, 43, 25, 46, 183, 131, 56, 244, 131, 33, 231, 70, 214, 234, 115, 245, 26, 218, 74, 27, 8, 15, 55, 158, 124, 231, 10, 137, 183, 0, 104, 167, 158, 84, 141, 235, 144, 5, 60, 254, 99, 154, 184, 180, 151, 191, 126, 225, 150, 77, 33, 234, 196, 173, 37, 189, 234, 101, 5, 242, 57, 73, 21, 146, 53, 200, 146, 27, 205, 187, 251, 222, 210, 254, 203, 136, 180, 248, 27, 243, 177, 96, 108, 233, 57, 7, 2, 158, 41, 138, 118, 136, 243, 52, 254, 134, 181, 80, 218, 48, 248, 126, 66, 68, 137, 19, 125, 148, 10, 139, 61, 71, 124, 8, 217 };

            var test = PublicKey.New(e, n);
           
            var roundtrip=Convert.ToBase64String(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey));

            //then
            Assert.AreEqual(2048, test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }
    }
}