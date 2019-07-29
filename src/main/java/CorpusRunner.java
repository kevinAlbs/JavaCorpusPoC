import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.MongoClientSettings;
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


public class CorpusRunner {
    private MongoClient client, client_encrypted;
    private ClientEncryption client_encryption;

    /* Check that all values of 'doc' that are deterministic with the same kms + type match 'val' */
    private static void deterministicCheck (BsonValue val, String match_kms, String match_type, BsonDocument doc) {
        for (String field : doc.keySet()) {
            if (field.equals("_id") || field.equals("altname_aws") || field.equals("altname_local")) {
                continue;
            }
            BsonDocument subdoc = doc.getDocument(field);

            String kms = subdoc.getString("kms").getValue();
            String type = subdoc.getString("type").getValue();
            String algo = subdoc.getString("algo").getValue();
            String method = subdoc.getString("method").getValue();
            String identifier = subdoc.getString("identifier").getValue();
            boolean allowed = subdoc.getBoolean("allowed").getValue();
            BsonValue value = subdoc.get("value");

            if (kms.equals(match_kms) && type.equals(match_type) && algo.equals("det")) {
                assert (val.equals(value));
            }
        }
    }

    private static void randomCheck (BsonValue val, String exclude_field, BsonDocument doc) {
        for (String field : doc.keySet()) {
            if (field.equals("_id") || field.equals("altname_aws") || field.equals("altname_local")) {
                continue;
            }

            if (field.equals(exclude_field)) {
                continue;
            }

            assert !doc.getDocument(field).get("value").equals(val);
        }
    }


    private void corpusTest (boolean useLocalSchema) {
        MongoClientSettings.Builder clientSettingsBuilder = MongoClientSettings.builder();
        /* TODO: figure out how this coded magic works */
        CodecRegistry codecRegistry = fromRegistries(
                fromCodecs(new UuidCodec(UuidRepresentation.STANDARD)), MongoClientSettings.getDefaultCodecRegistry());
        clientSettingsBuilder.codecRegistry(codecRegistry);
        MongoClientSettings clientSettings = clientSettingsBuilder.build();

        /* Step 1: create unencrypted client. */
        this.client = MongoClients.create(clientSettings);
        MongoDatabase db = client.getDatabase("db");

        /* Step 2: Drop and recreate db.coll with schema */
        db.getCollection("coll").drop();
        BsonDocument schema = Util.bsonDocumentFromPath("./corpus/corpus-schema.json");
        BsonDocument createCmd = new BsonDocument();
        createCmd.append("create", new BsonString("coll"));
        createCmd.append("validator", new BsonDocument("$jsonSchema", schema));
        db.runCommand(createCmd);

        /* Step 3: Drop and create admin.datakeys */
        MongoDatabase admin = client.getDatabase("admin");
        MongoCollection datakeys = admin.getCollection("datakeys", BsonDocument.class);
        datakeys.drop();
        datakeys.insertOne(Util.bsonDocumentFromPath("./corpus/corpus-key-aws.json"));
        datakeys.insertOne(Util.bsonDocumentFromPath("./corpus/corpus-key-local.json"));

        /* Step 4: Configure our objects. */
        Map kmsProviders = new HashMap();
        Map awsCreds = new HashMap(), localMasterkey = new HashMap();
        if (System.getenv("AWS_ACCESS_KEY_ID") == null ||
                System.getenv("AWS_SECRET_ACCESS_KEY") == null ||
                System.getenv("LOCAL_MASTERKEY") == null) {
            throw new IllegalArgumentException("no aws creds set");
        }
        awsCreds.put("accessKeyId", System.getenv("AWS_ACCESS_KEY_ID"));
        awsCreds.put("secretAccessKey", System.getenv("AWS_SECRET_ACCESS_KEY"));

        byte[] localMasterkeyBytes = Base64.getDecoder().decode(System.getenv("LOCAL_MASTERKEY"));
        localMasterkey.put("key", localMasterkeyBytes);
        kmsProviders.put ("aws", awsCreds);
        kmsProviders.put("local", localMasterkey);

        HashMap<String, BsonDocument> schemaMap = new HashMap<>();
        schemaMap.put("db.coll", schema);

        AutoEncryptionSettings.Builder autoEncryptionSettingsBuilder = AutoEncryptionSettings.builder()
                .keyVaultNamespace("admin.datakeys")
                .kmsProviders(kmsProviders);

        if (useLocalSchema) {
            autoEncryptionSettingsBuilder.schemaMap(schemaMap);
        }
        AutoEncryptionSettings autoEncryptionSettings = autoEncryptionSettingsBuilder.build();

        clientSettings = MongoClientSettings.builder()
                .codecRegistry(codecRegistry)
                .autoEncryptionSettings(autoEncryptionSettings)
                .build();
        this.client_encrypted = MongoClients.create (clientSettings);

        ClientEncryptionSettings clientEncryptionSettings = ClientEncryptionSettings.builder().
                keyVaultMongoClientSettings(MongoClientSettings.builder().build()).
                kmsProviders(kmsProviders).
                keyVaultNamespace("admin.datakeys").build();
        this.client_encryption = ClientEncryptions.create (clientEncryptionSettings);
        /* Step 5: Iterate over corpus. */
        BsonDocument corpus = Util.bsonDocumentFromPath("./corpus/corpus.json");
        BsonDocument corpus_copied = new BsonDocument();
        for (String field : corpus.keySet()) {
            if (field.equals("_id" ) || field.equals("altname_aws") || field.equals("altname_local")) {
                corpus_copied.append(field, corpus.get(field));
                continue;
            }

            String kms = corpus.getDocument(field).getString("kms").getValue();
            String type = corpus.getDocument(field).getString("type").getValue();
            String algo = corpus.getDocument(field).getString("algo").getValue();
            String method = corpus.getDocument(field).getString("method").getValue();
            String identifier = corpus.getDocument(field).getString("identifier").getValue();
            boolean allowed = corpus.getDocument(field).getBoolean("allowed").getValue();
            BsonValue value = corpus.getDocument(field).get("value");

            byte[] aws_key_id = Base64.getDecoder().decode("AWSAAAAAAAAAAAAAAAAAAA==");
            byte[] local_key_id = Base64.getDecoder().decode("LOCALAAAAAAAAAAAAAAAAA==");

            if (method.equals("auto")) {
                corpus_copied.append(field, corpus.get(field));
                continue;
            }

            assert (method.equals("explicit"));

            String algo_full = "AEAD_AES_256_CBC_HMAC_SHA_512-";
            if (algo.equals("rand")) algo_full  += "Random";
            if (algo.equals("det")) algo_full  += "Deterministic";
            EncryptOptions opts = new EncryptOptions(algo_full);
            if (identifier.equals("id")) {
                if (kms.equals("aws")) {
                    opts.keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, aws_key_id));
                } else {
                    assert (kms.equals("local"));
                    opts.keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, local_key_id));
                }
            } else {
                assert (identifier.equals("altname"));
                if (kms.equals("aws")) {
                    // TODO: key alt name support waiting on JAVA-3335. Use id for now.
                    // opts.keyAltName(new BsonString("aws"));
                    opts.keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, aws_key_id));
                } else {
                    assert (kms.equals("local"));
                    // TODO: key alt name support waiting on JAVA-3335. Use id for now.
                    // opts.keyAltName(new BsonString("local"));
                    opts.keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, local_key_id));
                }
            }
            boolean exceptionThrown = false;
            BsonValue encrypted = null;
            try {
                encrypted = client_encryption.encrypt (value, opts);
            } catch (Exception e) {
                System.out.println(e.getMessage());
                exceptionThrown = true;
            }
            System.out.println(field + " allowed? " + allowed + "value + " + value);
            // An exception is thrown if-and-only-if the method is prohibited.
            assert (exceptionThrown == !allowed);

            if (allowed) {
                assert (encrypted != null);
                BsonDocument doc = corpus.getDocument(field).clone();
                doc.put("value", encrypted); /* hope this overwrites */
                corpus_copied.append(field, doc);
            } else {
                corpus_copied.append(field, corpus.get(field));
            }
        }
        // Step 6: insert corpus_copied.
        MongoCollection coll_encrypted = client_encrypted.getDatabase("db").getCollection("coll", BsonDocument.class);
        coll_encrypted.insertOne(corpus_copied);

        // Step 7: check the auto decrypted document.
        BsonDocument corpus_decrypted = (BsonDocument)coll_encrypted.find(new BsonDocument()).first();
        System.out.println(corpus_decrypted);
        System.out.println(corpus);
        assert corpus_decrypted.equals(corpus);

        // Step 8: check the document with an unencrypted client.
        MongoCollection coll = client.getDatabase("db").getCollection("coll", BsonDocument.class);
        BsonDocument corpus_encrypted_actual = (BsonDocument) coll.find(new BsonDocument()).first();
        JsonWriterSettings toJsonSettings = JsonWriterSettings.builder().outputMode(JsonMode.EXTENDED).build();
        System.out.println (corpus_encrypted_actual.toJson(toJsonSettings));

        //JsonWriterSettings toJsonSettings = JsonWriterSettings.builder().outputMode(JsonMode.EXTENDED).build();
        System.out.println(corpus.toJson(toJsonSettings));
        System.out.println(corpus_decrypted.toJson(toJsonSettings));
        System.out.println (corpus_encrypted_actual.toJson(toJsonSettings));

        BsonDocument corpus_encrypted_expected = Util.bsonDocumentFromPath("./corpus/corpus-encrypted.json");

        for (String field : corpus_encrypted_actual.keySet()) {
            if (field.equals("_id") || field.equals("altname_aws") || field.equals("altname_local")) {
                continue;
            }

            String kms = corpus_encrypted_actual.getDocument(field).getString("kms").getValue();
            String type = corpus_encrypted_actual.getDocument(field).getString("type").getValue();
            String algo = corpus_encrypted_actual.getDocument(field).getString("algo").getValue();
            String method = corpus_encrypted_actual.getDocument(field).getString("method").getValue();
            String identifier = corpus_encrypted_actual.getDocument(field).getString("identifier").getValue();
            boolean allowed = corpus_encrypted_actual.getDocument(field).getBoolean("allowed").getValue();
            BsonValue value = corpus_encrypted_actual.getDocument(field).get("value");

            // All deterministic fields are an exact match.
            if (algo.equals("det")) {
                deterministicCheck(value, kms, type, corpus_encrypted_expected);
            }

            if (algo.equals("rand") && allowed) {
                randomCheck(value, field, corpus_encrypted_expected);
            }

            if (allowed) {
                BsonValue decrypted = client_encryption.decrypt(value.asBinary());
                assert (decrypted.equals(corpus.getDocument(field).get("value")));
            } else {
                assert (corpus_encrypted_actual.getDocument(field).get("value").equals(corpus.getDocument(field).get("value")));
            }
        }

    }

    private void run() {
        corpusTest(false);
        /* Step 9: run everything with a local schema. */
        corpusTest(true);
    }

    public static void main(String[] args) {
        new CorpusRunner().run();
    }
}
