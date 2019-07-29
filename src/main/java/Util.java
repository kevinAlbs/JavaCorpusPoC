import org.bson.BsonDocument;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Util {
    static BsonDocument bsonDocumentFromPath(String path) {
        try {
            return BsonDocument.parse(new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8));
        } catch (IOException ioe) {
            System.out.println(ioe);
            assert(false);
        }
        return null;
    }

    static void doAssert (boolean statement) {
        if (!statement) {
            throw new IllegalStateException("assertion failed");
        }
    }
}
