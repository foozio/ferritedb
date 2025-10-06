# FerriteDB Homebrew Formula

This directory contains the template used to publish FerriteDB via Homebrew. The
formula is meant to be copied into the `ferritedb/homebrew-tap` repository during
release.

## Release Workflow

1. Create a Git tag for the new version (e.g. `v0.2.0`) and push it to GitHub.
2. Download the auto-generated source tarball and compute its checksum:
   ```bash
   curl -sL -o /tmp/ferritedb-v0.2.0.tar.gz \
     https://github.com/foozio/ferritedb/archive/refs/tags/v0.2.0.tar.gz
   shasum -a 256 /tmp/ferritedb-v0.2.0.tar.gz
   ```
3. Update `packaging/homebrew/ferritedb.rb` with the new `url`, `sha256`, and
   `version` if necessary.
4. Copy the formula into the tap repository and push:
   ```bash
   git clone git@github.com:ferritedb/homebrew-tap.git
   cp packaging/homebrew/ferritedb.rb homebrew-tap/Formula/
   cd homebrew-tap
   git commit -am "ferritedb v0.2.0"
   git push origin main
   ```
5. Validate the formula:
   ```bash
   brew install --build-from-source ferritedb/tap/ferritedb
   brew test ferritedb/tap/ferritedb
   brew audit --new-formula --strict ferritedb/tap/ferritedb
   ```

Users can then install the binary with:

```bash
brew tap ferritedb/tap
brew install ferritedb
```

`SQLX_OFFLINE` is set by the formula so Homebrew bottles build without contacting
a live database.
