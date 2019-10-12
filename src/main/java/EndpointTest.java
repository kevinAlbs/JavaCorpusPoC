import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoException;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.model.vault.EncryptOptions;
import com.mongodb.client.vault.ClientEncryption;
import com.mongodb.client.vault.ClientEncryptions;
import com.mongodb.crypt.capi.MongoCryptException;
import org.bson.*;
import org.bson.codecs.UuidCodec;
import org.bson.codecs.configuration.CodecRegistry;

import java.util.*;

import static org.bson.codecs.configuration.CodecRegistries.fromCodecs;
import static org.bson.codecs.configuration.CodecRegistries.fromRegistries;

public class EndpointTest {
    private ClientEncryption clientEncryption;

    private void expect_failure (DataKeyOptions opts, String errorMessage) {
        String actualErrorMessage = "";
        try {
            BsonBinary uuid = clientEncryption.createDataKey("aws", opts);
        } catch (MongoException exception) {
            actualErrorMessage = exception.getMessage();
        }
        Util.doAssert(actualErrorMessage.contains(errorMessage));
    }
    private void expect_success (DataKeyOptions opts) {
        BsonBinary uuid = clientEncryption.createDataKey("aws", opts);

        /* Encrypt and decrypt something. */
        BsonBinary encrypted = clientEncryption.encrypt (
                new BsonString("test"),
                new EncryptOptions("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic").keyId(uuid));
        BsonValue value = clientEncryption.decrypt (encrypted);
        Util.doAssert (value.asString().getValue().equals("test"));
    }

    private void run() {
        MongoClientSettings.Builder clientSettingsBuilder = MongoClientSettings.builder();
        CodecRegistry codecRegistry = fromRegistries(
                fromCodecs(new UuidCodec(UuidRepresentation.STANDARD)), MongoClientSettings.getDefaultCodecRegistry());

        Map kmsProviders = new HashMap();
        Map awsCreds = new HashMap();
        if (System.getenv("AWS_ACCESS_KEY_ID") == null ||
                System.getenv("AWS_SECRET_ACCESS_KEY") == null ||
                System.getenv("LOCAL_MASTERKEY") == null) {
            throw new IllegalArgumentException("no aws creds set");
        }
        awsCreds.put("accessKeyId", System.getenv("AWS_ACCESS_KEY_ID"));
        awsCreds.put("secretAccessKey", System.getenv("AWS_SECRET_ACCESS_KEY"));
        kmsProviders.put ("aws", awsCreds);

        MongoClientSettings clientSettings = MongoClientSettings.builder()
                .codecRegistry(codecRegistry)
                .build();

        ClientEncryptionSettings clientEncryptionSettings = ClientEncryptionSettings.builder().kmsProviders(kmsProviders).keyVaultNamespace("admin.datakey").keyVaultMongoClientSettings(clientSettings).build();
        this.clientEncryption = ClientEncryptions.create(clientEncryptionSettings);

        /* No endpoint, should succeed. */
        DataKeyOptions dataKeyOptions;

        dataKeyOptions = new DataKeyOptions().
                masterKey(new BsonDocument()
                        .append("key", new BsonString("arn:aws:kms:us-east-1:579766882180:key/89fcc2c4-08b0-4bd9-9f25-e30687b580d0"))
                        .append("region", new BsonString("us-east-1")));
        expect_success(dataKeyOptions);


        /* Endpoint same as default, should still succeed. */
        dataKeyOptions = new DataKeyOptions().
                masterKey(new BsonDocument()
                        .append("key", new BsonString("arn:aws:kms:us-east-1:579766882180:key/89fcc2c4-08b0-4bd9-9f25-e30687b580d0"))
                        .append("region", new BsonString("us-east-1"))
                        .append ("endpoint", new BsonString("kms.us-east-1.amazonaws.com")));
        expect_success(dataKeyOptions);
        

        /* Endpoint to incorrect region should fail with a reasonable message from AWS. */
        dataKeyOptions = new DataKeyOptions().
                masterKey(new BsonDocument()
                        .append("key", new BsonString("arn:aws:kms:us-east-1:579766882180:key/89fcc2c4-08b0-4bd9-9f25-e30687b580d0"))
                        .append("region", new BsonString("us-east-1"))
                        .append ("endpoint", new BsonString("kms.us-east-2.amazonaws.com")));
        expect_failure(dataKeyOptions, "Credential should be scoped to a valid region, not 'us-east-1'.");

        /* Endpoint to example.com should fail because it's just wrong. */
        dataKeyOptions = new DataKeyOptions().
                masterKey(new BsonDocument()
                        .append("key", new BsonString("arn:aws:kms:us-east-1:579766882180:key/89fcc2c4-08b0-4bd9-9f25-e30687b580d0"))
                        .append("region", new BsonString("us-east-1"))
                        .append ("endpoint", new BsonString("example.com")));
        expect_failure(dataKeyOptions, "Got parse error");
    }

    public static void main(String[] args) {
        new EndpointTest().run();
    }
}
