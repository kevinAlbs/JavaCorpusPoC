import com.mongodb.*;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.vault.EncryptOptions;
import com.mongodb.client.vault.ClientEncryption;
import com.mongodb.client.vault.ClientEncryptions;
import org.bson.*;
import org.bson.codecs.UuidCodec;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.json.JsonMode;
import org.bson.json.JsonWriterSettings;
import java.util.*;

import static org.bson.codecs.configuration.CodecRegistries.fromCodecs;
import static org.bson.codecs.configuration.CodecRegistries.fromRegistries;

public class ExternalKeyVaultTest {
    private MongoClient client, client_encrypted;
    private ClientEncryption client_encryption;

    private void runAuth (boolean withExternalKeyVault) {
        MongoClientSettings.Builder clientSettingsBuilder = MongoClientSettings.builder();
        /* TODO: figure out how this codec magic works */
        CodecRegistry codecRegistry = fromRegistries(
                fromCodecs(new UuidCodec(UuidRepresentation.STANDARD)), MongoClientSettings.getDefaultCodecRegistry());
        clientSettingsBuilder.codecRegistry(codecRegistry);
        MongoClientSettings clientSettings = clientSettingsBuilder.build();

        /* Step 1: create unencrypted client and recreate keys collection */
        this.client = MongoClients.create(clientSettings);
        MongoDatabase db = client.getDatabase("db");
        MongoDatabase admin = client.getDatabase("admin");
        MongoCollection datakeys = admin.getCollection("datakeys", BsonDocument.class);
        datakeys.drop();
        datakeys.insertOne(Util.bsonDocumentFromPath("./external/external-key.json"));

        /* Step 2: create encryption objects. */
        Map kmsProviders = new HashMap();
        Map localMasterkey = new HashMap();
        Map schemaMap = new HashMap();

        byte[] localMasterkeyBytes = Base64.getDecoder().decode(System.getenv("LOCAL_MASTERKEY"));
        localMasterkey.put("key", localMasterkeyBytes);
        kmsProviders.put("local", localMasterkey);
        schemaMap.put("db.coll", Util.bsonDocumentFromPath("./external/external-schema.json"));

        MongoClientSettings externalClientSettings =  MongoClientSettings.builder()
                .codecRegistry(codecRegistry)
                .credential(MongoCredential.createCredential("fake-user", "admin","fake-pwd".toCharArray())).build();

        AutoEncryptionSettings.Builder autoEncryptionSettingsBuilder = AutoEncryptionSettings.builder()
                .keyVaultNamespace("admin.datakeys")
                .kmsProviders(kmsProviders)
                .schemaMap(schemaMap);
        if (withExternalKeyVault) {
            autoEncryptionSettingsBuilder.keyVaultMongoClientSettings(externalClientSettings);
        }

        AutoEncryptionSettings autoEncryptionSettings = autoEncryptionSettingsBuilder.build();

        clientSettings = MongoClientSettings.builder()
                .codecRegistry(codecRegistry)
                .autoEncryptionSettings(autoEncryptionSettings)
                .build();
        this.client_encrypted = MongoClients.create (clientSettings);

        ClientEncryptionSettings.Builder clientEncryptionSettingsBuilder = ClientEncryptionSettings.builder().
                keyVaultMongoClientSettings(MongoClientSettings.builder().build())
                .kmsProviders(kmsProviders)
                .keyVaultNamespace("admin.datakeys");

        if (withExternalKeyVault) {
            clientEncryptionSettingsBuilder.keyVaultMongoClientSettings(externalClientSettings);
        }

        ClientEncryptionSettings clientEncryptionSettings = clientEncryptionSettingsBuilder.build();
        this.client_encryption = ClientEncryptions.create (clientEncryptionSettings);

        boolean authExceptionThrown = false;
        MongoCollection coll = this.client_encrypted.getDatabase("db")
                .getCollection("coll", BsonDocument.class);
        try {
            coll.insertOne(new BsonDocument().append("encrypted", new BsonString("test")));
        } catch (MongoSecurityException mse) {
            authExceptionThrown = true;
        }
        Util.doAssert (authExceptionThrown == withExternalKeyVault);

        EncryptOptions encryptOptions = new EncryptOptions("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic")
                .keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, Base64.getDecoder().decode("LOCALAAAAAAAAAAAAAAAAA==")));
        authExceptionThrown = false;
        try {
            client_encryption.encrypt(new BsonString("test"), encryptOptions);
        } catch (MongoSecurityException mse) {
            authExceptionThrown = true;
        }
        Util.doAssert (authExceptionThrown == withExternalKeyVault);
    }

    private void run () {
        runAuth (false);
        runAuth (true);
    }

    public static void main(String[] args) {
        new ExternalKeyVaultTest().run();
    }
}
