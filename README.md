A Java PoC for running some FLE prose tests:
https://github.com/mongodb/specifications/pull/579

Set the following environment variables to run:
- AWS_ACCESS_KEY_ID (from BUILD-7242)
- AWS_SECRET_ACCESS_KEY (from BUILD-7242)
- LOCAL_MASTERKEY to `Mng0NCt4ZHVUYUJCa1kxNkVyNUR1QURhZ2h2UzR2d2RrZzh0cFBwM3R6NmdWMDFBMUN3YkQ5aXRRMkhGRGdQV09wOGVNYUMxT2k3NjZKelhaQmRCZGJkTXVyZG9uSjFk`.

I've been running with IntelliJ and setting the following VM variables:
```
-Djna.library.path="/Users/kevinalbertson/code/libmongocrypt/cmake-build" -enableassertions
```

Note, passing the test requires libmongocrypt on master.
