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

public class ViewTest {
    private MongoClient client, client_encrypted;

    private void run () {
        MongoClientSettings.Builder clientSettingsBuilder = MongoClientSettings.builder();
        CodecRegistry codecRegistry = fromRegistries(
                fromCodecs(new UuidCodec(UuidRepresentation.STANDARD)), MongoClientSettings.getDefaultCodecRegistry());
        clientSettingsBuilder.codecRegistry(codecRegistry);
        MongoClientSettings clientSettings = clientSettingsBuilder.build();
        client = MongoClients.create(clientSettings);

        client.getDatabase("db").getCollection("view").drop();
        BsonDocument createCmd = new BsonDocument().append("create", new BsonString("view")).append("viewOn", new BsonString("coll"));
        BsonDocument doc = client.getDatabase("db").runCommand(createCmd, BsonDocument.class);
        System.out.println(doc);


        Map kmsProviders = new HashMap();
        Map localMasterkey = new HashMap();

        byte[] localMasterkeyBytes = Base64.getDecoder().decode(System.getenv("LOCAL_MASTERKEY"));
        localMasterkey.put("key", localMasterkeyBytes);
        kmsProviders.put("local", localMasterkey);

        AutoEncryptionSettings.Builder autoEncryptionSettingsBuilder = AutoEncryptionSettings.builder()
                .keyVaultNamespace("admin.datakeys")
                .kmsProviders(kmsProviders);

        AutoEncryptionSettings autoEncryptionSettings = autoEncryptionSettingsBuilder.build();

        clientSettings = MongoClientSettings.builder()
                .codecRegistry(codecRegistry)
                .autoEncryptionSettings(autoEncryptionSettings)
                .build();
        this.client_encrypted = MongoClients.create (clientSettings);


        boolean exceptionThrown = false;
        MongoCollection coll = this.client_encrypted.getDatabase("db")
                .getCollection("view", BsonDocument.class);
        try {
            coll.insertOne(new BsonDocument().append("encrypted", new BsonString("test")));
        } catch (MongoException me) {
            exceptionThrown = true;
            Util.doAssert(me.getMessage().contains("cannot auto encrypt a view"));
        }
        Util.doAssert(exceptionThrown);
    }


    public static void main(String[] args) {
        new ViewTest().run();
    }
}
