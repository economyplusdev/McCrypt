using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace McCrypt
{
    public class Keys
    {
        private static Random rng = new Random();
        public static string KeyDbFile = "";
        internal struct content
        {
            public string FriendlyId;
            public byte[] ContentKey;
        }

        private static string lastDeviceId = "";
        private static List<content> contentList = new List<content>();
        private static byte[] deriveUserKey(string UserId, string DeviceId)
        {
            byte[] userBytes = Encoding.Unicode.GetBytes(UserId);
            byte[] deviceBytes = Encoding.Unicode.GetBytes(DeviceId);

            int kLen = userBytes.Length;
            if (deviceBytes.Length < kLen)
                kLen = deviceBytes.Length;

            byte[] key = new byte[kLen];

            for (int i = 0; i < kLen; i++)
            {
                key[i] = (byte)(deviceBytes[i] ^ userBytes[i]);
            }

            return key;
        }
        internal static string GenerateKey()
        {
            string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            string key = "";
            for (int i = 0; i < 32; i++)
            {
                key += allowedChars[rng.Next(0, allowedChars.Length)];
            }
            return key;
        }
        private static byte[] deriveContentKey(byte[] UserKey, byte[] ContentKey)
        {
            int kLen = UserKey.Length;
            if (ContentKey.Length < kLen)
                kLen = ContentKey.Length;

            byte[] key = new byte[kLen];

            for (int i = 0; i < kLen; i++)
            {
                key[i] = (byte)(UserKey[i] ^ ContentKey[i]);
            }

            int ckLen = kLen / 2;
            byte[] contentKey = new byte[ckLen];

            for (int i = 0; i < kLen; i += 2)
            {
                contentKey[i / 2] = key[i];
            }

            return contentKey;
        }

        public static void AddKey(string FriendlyId, byte[] ContentKey, bool addToKeyCache = true)
        {
            if (LookupKey(FriendlyId) != null)
                return;

            string keyCacheEntry = FriendlyId + "=" + Encoding.UTF8.GetString(ContentKey);
#if DEBUG
            Console.WriteLine(keyCacheEntry);
#endif

            if (addToKeyCache && KeyDbFile != "")
                File.AppendAllText(KeyDbFile, keyCacheEntry + "\n");

            content content = new content();
            content.FriendlyId = FriendlyId;
            content.ContentKey = ContentKey;

            contentList.Add(content);
        }

        private static void readReceipt(string receiptData)
        {
            dynamic recData = JsonConvert.DeserializeObject(receiptData);
            string userId = recData.Receipt.EntityId;
            string deviceId = "";

            if (recData.Receipt.ReceiptData != null)
                deviceId = recData.Receipt.ReceiptData.DeviceId;

            if (deviceId == "" || deviceId == null)
                deviceId = lastDeviceId;

            if (deviceId == "" || deviceId == null)
                return;

            lastDeviceId = deviceId;

            byte[] userKey = deriveUserKey(userId, deviceId);

            // Derive content keys
            int totalEntitlements = recData.Receipt.Entitlements.Count;

            for (int i = 0; i < totalEntitlements; i++)
            {
                try
                {
                    string friendlyId = recData.Receipt.Entitlements[i].FriendlyId;
                    string contentKeyB64 = recData.Receipt.Entitlements[i].ContentKey;
                    if (contentKeyB64 == null)
                        continue;

                    byte[] contentKey = Utils.ForceDecodeBase64(contentKeyB64);
                    byte[] realContentKey = deriveContentKey(userKey, contentKey);

                    AddKey(friendlyId, realContentKey);

                }
                catch (Exception) { continue; }
            }

        }

        public static void ReadEntitlementFile(string entPath)
        {
            string jsonData = File.ReadAllText(entPath);
            dynamic entData = JsonConvert.DeserializeObject(jsonData);
            string receiptB64 = entData.Receipt;

            if (receiptB64 == null)
                return;

            if (receiptB64.Split('.').Length <= 1)
                return;

            string receiptData = Encoding.UTF8.GetString(Utils.ForceDecodeBase64(receiptB64.Split('.')[1]));
            readReceipt(receiptData);
            int totalItems = entData.Items.Count;
            for (int i = 0; i < totalItems; i++)
            {
                string b64Data = entData.Items[i].Receipt;

                if (b64Data == null)
                    continue;

                if (b64Data.Split('.').Length <= 1)
                    continue;

                string recept = Encoding.UTF8.GetString(Utils.ForceDecodeBase64(b64Data.Split('.')[1]));
                readReceipt(recept);
            }
        }
        public static void ReadKeysDb(string keyFile)
        {
            KeyDbFile = keyFile;
            string[] keyList = File.ReadAllLines(keyFile);
            foreach (string key in keyList)
            {
                if (key.Contains('='))
                {
                    string[] keys = key.Split('=');
                    if (keys.Length >= 2)
                    {
                        string friendlyId = keys[0];
                        byte[] contentKey = Encoding.UTF8.GetBytes(keys[1]);
                        AddKey(friendlyId, contentKey, false);
                    }
                }
            }
        }
        public static byte[] LookupKey(string FriendlyId)
        {
            foreach (content content in contentList)
            {
                if (content.FriendlyId == FriendlyId)
                    return content.ContentKey;
            }
            return null;
        }
    }
}
