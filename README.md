<p align="center">
    <a href="https://stalw.art">
    <img src="https://raw.githubusercontent.com/stalwartlabs/stalwart/main/img/logo-red.svg" height="150">
    </a>
</p>

<h3 align="center">
  Stalwart Migration Tool
</h3>

<br>

<p align="center">
  <a href="https://github.com/stalwartlabs/stalwart-migrate/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/stalwartlabs/stalwart-migrate/ci.yml?style=flat-square&label=CI" alt="CI"></a>
  &nbsp;
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg?label=license&style=flat-square" alt="License: AGPL v3"></a>
  &nbsp;
  <a href="https://stalw.art/docs/install/get-started"><img src="https://img.shields.io/badge/read_the-docs-red?style=flat-square" alt="Documentation"></a>
</p>
<p align="center">
  <a href="https://mastodon.social/@stalwartlabs"><img src="https://img.shields.io/mastodon/follow/109929667531941122?style=flat-square&logo=mastodon&color=%236364ff&label=Follow%20on%20Mastodon" alt="Mastodon"></a>
  &nbsp;
  <a href="https://twitter.com/stalwartlabs"><img src="https://img.shields.io/twitter/follow/stalwartlabs?style=flat-square&logo=x&label=Follow%20on%20Twitter" alt="Twitter"></a>
</p>
<p align="center">
  <a href="https://discord.com/servers/stalwart-923615863037390889"><img src="https://img.shields.io/discord/923615863037390889?label=Join%20Discord&logo=discord&style=flat-square" alt="Discord"></a>
  &nbsp;
  <a href="https://www.reddit.com/r/stalwartlabs/"><img src="https://img.shields.io/reddit/subreddit-subscribers/stalwartlabs?label=Join%20%2Fr%2Fstalwartlabs&logo=reddit&style=flat-square" alt="Reddit"></a>
</p>


`stalwart-migrate` moves the data of a [Stalwart Mail and Collaboration Server](https://stalw.art) v0.16.27 deployment to Stalwart v1, and can move it back again if the upgrade has to be reverted.

Stalwart v1 changes the on-disk layout of the data store, so a v0.16 store cannot be upgraded in place. The tool instead copies every account, message, calendar, address book, file and setting from the running v0.16 store into a new, empty v1 store, converting each object with the v1 code as it goes. The copy can be repeated while v0.16 keeps serving users; each repetition transfers only what changed, so the final switch needs only a short downtime window.

## Overview

| | |
|---|---|
| `prepare` | Review how the v0.16 settings convert to v1, answer the questions that need an operator decision, and record the answers. |
| `run` | Copy the data into the v1 store. Safe to repeat and to interrupt; each run copies only what changed since the previous one. |
| `run --final` | With v0.16 stopped, copy the last changes, finalize the v1 store and verify it. |
| `verify` | Compare the v0.16 and v1 stores, on a sample of accounts or in full. |
| `status` | Show progress, accounts in error and recent runs. |
| `report` | List every object that was dropped, changed, truncated or could not be copied. |
| `rollback` | Copy a v1 store back into a new, empty v0.16 store. |

## Migration scope

The migration is a copy. The tool opens the v0.16 data store read-only and never writes to it, so the original deployment stays intact and keeps working throughout the migration and after it. Everything the tool writes goes into the new v1 store named on the command line, which must be empty when the first run starts.

Users notice little of the switch, because the tool preserves the identifiers that clients cache. Account ids, document ids, thread ids, IMAP UIDs and UIDVALIDITY values, and the per-account change history all keep their v0.16 values, so IMAP clients do not download their mailboxes again and JMAP clients continue their synchronisation from where they stopped. A few effects remain visible after the switch:

- OAuth tokens issued by v0.16 are not migrated, so users sign in again in OAuth clients.
- CalDAV, CardDAV and WebDAV clients fetch their calendars, contacts and files once more, because the entity tags change. Their synchronisation tokens stay valid.
- The full-text search index is not copied. v1 rebuilds it after it starts, and searches return incomplete results until the rebuild finishes.

Settings are converted by name from the v0.16 schema to the v1 schema. Most conversions are automatic. The few that involve a change of behaviour (OpenID Connect directories, client address detection behind a reverse proxy, AI models and several others) are presented to the operator by `prepare`, which explains the difference and records the decision. Every setting or object that cannot be represented in v1 is listed in the run report. The full list of schema differences between the two versions is in [SCHEMA_CHANGES.md](SCHEMA_CHANGES.md).

The tool does not migrate in place, does not upgrade older v0.16 releases, and does not modify any external service that v0.16 uses: search engines, in-memory and lookup stores, directories, cluster coordinators and telemetry stores are never opened. The only change it ever makes outside the new v1 store concerns the learned spam filter model in a shared blob store, described in [Shared blob stores](#shared-blob-stores).

### Supported stores

The tool reads and writes the data store backends that Stalwart supports:

- RocksDB
- SQLite
- PostgreSQL
- MySQL
- FoundationDB

Message bodies, attachments and files may live in the data store itself or in an external blob store: S3 and S3-compatible services, Azure Blob Storage, the file system, or a sharded combination of these. The source and target may use different data store backends, since the target is defined independently of the source.

The settings and data of every feature are migrated, including tenants, AI models, masked email addresses, alerts, sharded stores, archived items, and stored traces and metrics.

## Requirements

Before the migration starts, the deployment must meet these conditions:

- The source runs Stalwart v0.16.27. Earlier 0.16 releases must be upgraded to 0.16.27 first.
- The target is a new, empty store: a new PostgreSQL or MySQL database, a new FoundationDB cluster, or a new RocksDB directory or SQLite file. A PostgreSQL database may contain extensions and the schemas of other applications, provided those schemas are not on the search path of the user the tool connects as.
- There is room for a second copy of the data store. With a shared external blob store, only the data store is duplicated, because message bodies and files stay where they are.
- Every v0.16 node is stopped for the final run. Incremental runs before it can read a live server.
- The tool runs on a host that can reach both stores with the same paths and network names that the servers use, or the differences are bridged with `--path-map` and `--target-path-map` (see [Paths and file ownership](#paths-and-file-ownership)).

## Installation

`stalwart-migrate` is published as prebuilt binaries for Linux and macOS and as a Docker image. Install it on a host that meets the [requirements](#requirements). For a Docker deployment, the image is the recommended choice because it sees the same paths, networks and file ownership as the Stalwart container. Windows is not supported natively, so Windows hosts run the Docker image or the Linux binary in WSL.

The standard build supports every data store and blob store except FoundationDB. Deployments on FoundationDB install the `-fdb` build, which adds FoundationDB to the standard build. It is available for Linux on x86_64 and aarch64 with glibc 2.34 or later, and requires the FoundationDB 7.4 client library (`libfdb_c.so`) on the host; the `-fdb` image already contains it.

The standard build is the right one for the official Stalwart binaries and Docker images, whether or not an Enterprise license is installed. Only a Stalwart server compiled from source without the `enterprise` feature needs the `-oss` version of the tool instead (the `--oss` option of the install script, the `stalwart-migrate-oss-<target>.tar.xz` archives, or the image tags ending in `-oss`).

### Install script

The install script detects the operating system and CPU, downloads the matching archive of the latest release, verifies its SHA-256 checksum and installs the binary:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/stalwartlabs/stalwart-migrate/releases/latest/download/stalwart-migrate-installer.sh | sh
```

Options are passed to the script after `sh -s --`, for example `| sh -s -- --fdb`:

| Option | Effect |
|---|---|
| `--fdb` | Installs the `-fdb` build. |
| `--version <VER>` | Installs release `<VER>` (for example `1.0.0`) instead of the latest one. |
| `--to <DIR>` | Installs into `<DIR>`. Without it, the binary goes to `/usr/local/bin` when the script runs as root and to `~/.local/bin` otherwise. The `STALWART_MIGRATE_INSTALL_DIR` environment variable has the same effect. |
| `--musl` | On Linux, installs the statically linked musl build. |

On Linux the script installs the glibc build when the host has glibc 2.28 or later, and the musl build otherwise, for example on Alpine Linux.

### Manual download

Every release on the [releases page](https://github.com/stalwartlabs/stalwart-migrate/releases) carries one archive per build and platform, named `stalwart-migrate-<target>.tar.xz` for the standard build and `stalwart-migrate-fdb-<target>.tar.xz` for the `-fdb` build:

| Platform | Target |
|---|---|
| Linux x86_64 (glibc) | `x86_64-unknown-linux-gnu` |
| Linux x86_64 (musl, static) | `x86_64-unknown-linux-musl` |
| Linux aarch64 (glibc) | `aarch64-unknown-linux-gnu` |
| Linux aarch64 (musl, static) | `aarch64-unknown-linux-musl` |
| Linux ARMv7 (glibc) | `armv7-unknown-linux-gnueabihf` |
| Linux ARMv7 (musl, static) | `armv7-unknown-linux-musleabihf` |
| macOS Apple silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |

The `-fdb` archives exist only for the two glibc targets on x86_64 and aarch64, and the ARMv7 archives are built on a best-effort basis, so a release may lack them. Each archive contains the `stalwart-migrate` binary, this README and the license texts, and comes with a `.sha256` file, while `sha256.sum` lists the checksums of all archives and of the install script. The archives also carry GitHub build provenance attestations:

```sh
sha256sum -c stalwart-migrate-x86_64-unknown-linux-gnu.tar.xz.sha256
gh attestation verify stalwart-migrate-x86_64-unknown-linux-gnu.tar.xz --repo stalwartlabs/stalwart-migrate
tar -xJf stalwart-migrate-x86_64-unknown-linux-gnu.tar.xz
sudo install -m 0755 stalwart-migrate-x86_64-unknown-linux-gnu/stalwart-migrate /usr/local/bin/
```

The macOS binaries are not notarized. macOS therefore refuses to run a binary from an archive downloaded with a web browser, which marks the file as quarantined, until the quarantine attribute is removed with `xattr -d com.apple.quarantine stalwart-migrate`. Archives downloaded with the install script or with `curl` are not quarantined.

### Docker image

The image `stalwartlabs/stalwart-migrate` is published on Docker Hub and as `ghcr.io/stalwartlabs/stalwart-migrate` for `linux/amd64` and `linux/arm64`. Its tags follow the releases (`1.0.0`, `1.0`, `latest`), and the `-fdb` image uses the same tags with a suffix (`1.0.0-fdb`, `latest-fdb`). The images are signed with cosign.

The image is built on the same base as the Stalwart image and runs as the same `stalwart` user (uid and gid 2000), so the files it creates in the v1 store are owned by the user the v1 container runs as. It declares these volumes:

| Path | Content |
|---|---|
| `/etc/stalwart` | The v0.16 configuration directory, as in the Stalwart image. |
| `/var/lib/stalwart` | The v0.16 data directory, as in the Stalwart image. |
| `/etc/stalwart-v1` | The configuration directory of the new v1 server. |
| `/var/lib/stalwart-v1` | The data directory of the new v1 server. |
| `/var/lib/stalwart-migrate` | The [state directory](#state-directory). |

The entry point is `stalwart-migrate`, so the command and its options follow the image name. Run the container on the network of the Stalwart deployment, with the environment file of the Stalwart service and its volumes, so that it reaches the stores under the same names and paths as the server:

```sh
docker run --rm -it \
  --network <compose-network> \
  --env-file <same env as the stalwart service> \
  -v <stalwart-etc-volume>:/etc/stalwart:ro \
  -v <stalwart-data-volume>:/var/lib/stalwart \
  -v <new-v1-etc-volume>:/etc/stalwart-v1 \
  -v <new-v1-data-volume>:/var/lib/stalwart-v1 \
  -v <migrate-state-volume>:/var/lib/stalwart-migrate \
  stalwartlabs/stalwart-migrate:<version> run \
    --source /etc/stalwart/config.json \
    --target /etc/stalwart-v1/config.json \
    --state /var/lib/stalwart-migrate
```

With Docker Compose, the same setup is a service that shares the network, volumes and environment file of the `stalwart` service. The `migrate` profile keeps it from starting with the rest of the deployment:

```yaml
services:
  migrate:
    image: stalwartlabs/stalwart-migrate:<version>
    profiles: [migrate]
    env_file: stalwart.env
    volumes:
      - stalwart-etc:/etc/stalwart:ro
      - stalwart-data:/var/lib/stalwart
      - stalwart-v1-etc:/etc/stalwart-v1
      - stalwart-v1-data:/var/lib/stalwart-v1
      - migrate-state:/var/lib/stalwart-migrate

volumes:
  stalwart-v1-etc:
  stalwart-v1-data:
  migrate-state:
```

Each command then runs with `docker compose run --rm migrate <command> <options>`, for example `docker compose run --rm migrate prepare --source /etc/stalwart/config.json --state /var/lib/stalwart-migrate`. The `stalwart-etc` and `stalwart-data` volumes are those already declared for the `stalwart` service.

The paths in the target configuration are the paths that the tool writes to, and the v1 server reads the same configuration. The v1 container must therefore mount the new data volume at the path the target configuration names, `/var/lib/stalwart-v1` in these examples, while its configuration volume can be mounted at the usual `/etc/stalwart`. When the v1 container should mount its data at `/var/lib/stalwart` instead, the target configuration names `/var/lib/stalwart` and the tool is run with `--target-path-map /var/lib/stalwart=/var/lib/stalwart-v1`, as described in [Paths and file ownership](#paths-and-file-ownership).

## Concepts

### Configuration files

Both servers are described to the tool by their local configuration file, the `config.json` that defines the data store. The tool reads the remaining settings from the registry inside the store. `--source` names the v0.16 configuration and `--target` the configuration the v1 server will use, so the same file can later be mounted as the configuration of the v1 server. A RocksDB target, for example, is defined as:

```json
{
  "@type": "RocksDb",
  "path": "/var/lib/stalwart-v1/"
}
```

A PostgreSQL target names a new database:

```json
{
  "@type": "PostgreSql",
  "host": "db.example.org",
  "port": 5432,
  "database": "stalwart_v1",
  "authUsername": "stalwart",
  "authSecret": { "@type": "Value", "secret": "<password>" }
}
```

The tool records a fingerprint of both definitions in its state and refuses to continue a migration with a different source or target.

### State directory

All progress lives in the state directory named by `--state` (or the `STALWART_MIGRATE_STATE` environment variable). It holds the answers recorded by `prepare`, a SQLite database with the position of every account and every reported issue, and the logs of each command. Every later command of the same migration uses the same state directory, and `rollback` reads it to restore the original v0.16 settings, so it must be kept until the v0.16 deployment is retired.

The state directory must lie outside every store: the tool refuses a state directory inside or overlapping the v0.16 or v1 data store or a file system blob store.

### Data categories

The data is divided into categories that can be selected individually:

| Category | Content | Default |
|---|---|---|
| `settings` | Server settings | on |
| `principals` | Accounts, groups, domains and other principals | on |
| `mail` | Mailboxes, emails and submissions | on |
| `calendars` | Calendars and events | on |
| `contacts` | Address books and contacts | on |
| `files` | Files | on |
| `sieve` | Sieve scripts | on |
| `identities` | Identities | on |
| `push_subscriptions` | Push subscriptions | on |
| `spam_samples` | Spam training samples | on |
| `reports` | Received DMARC, TLS and ARF reports | on |
| `archive` | Archived items | on |
| `spam_model` | Learned spam filter models; final run only | on |
| `queue` | MTA queue and the outbound DMARC and TLS report aggregation; final run only | on |
| `tasks` | Scheduled tasks; final run only | on |
| `telemetry` | Stored traces and metrics | on |

Categories marked "final run only" are skipped by incremental runs even when selected and copied only by `run --final`, when v0.16 is stopped. This keeps the queue and scheduled tasks from being delivered or run twice while both servers run.

## Preparing the migration

`prepare` reads the v0.16 settings, converts them to v1 and asks the operator about every conversion that needs a decision. It runs interactively and needs a terminal:

```sh
stalwart-migrate prepare \
  --source /etc/stalwart/config.json \
  --state /var/lib/stalwart-migrate
```

The questions are grouped in sections (Target, Data categories, Authentication, Network, AI and spam filtering, Other settings). Each question shows how v0.16 behaved, how v1 behaves, and, where one exists, a recommendation. Pressing Enter accepts the value in brackets. The data categories to migrate are always asked, with every category selected by default. When v0.16 keeps its blobs in an external blob store, `prepare` also asks whether v1 reuses it (recommended, no copy) or every blob is copied into the target; blobs kept in the v0.16 data store are always copied, without a question.

The v1 edition is not asked: it is the build of the tool, which must match the build of the v1 server (see [Installation](#installation)). An `answers.toml` written by an earlier version may still name an edition in `[global.edition]`; `prepare` and `run` refuse one that names the other build, and `prepare` drops it when it rewrites the file.

The remaining questions appear only when the v0.16 settings contain the object concerned:

| Question | Asked when |
|---|---|
| OpenID Connect directory | for every OIDC directory: accepted audiences, opaque token validation, and the access granted to tokens without Stalwart scopes |
| OAuth token lifetimes | an OIDC provider uses lifetimes below the v1 minimums |
| OAuth client registration | for every OIDC provider, because v1 rejects unregistered client ids |
| Counter reads in expressions | an expression calls `counter_get`, which v1 no longer has |
| Client address behind a reverse proxy | `useXForwarded` is enabled: the header and the number of trusted proxies |
| AI spam classifier | the LLM spam classifier is enabled |
| AI model provider | for every AI model |
| RFC 2136 DNS server with SIG(0) | a DNS server uses SIG(0), which v1 does not support |
| Azure blob store authentication | an Azure store has neither an access key nor a SAS token |
| In-memory store in a cluster | a cluster coordinator is enabled while the in-memory store is the default one (the data store), which v1 refuses: it needs a Redis, Redis Cluster, Redis Sentinel or sharded Redis store |
| Features missing from the v1 server build | the tool is the open source build and the v0.16 settings use enterprise-only objects, which it cannot store |
| New permissions | custom roles grant permissions that have new v1 counterparts |
| Changed defaults | settings still hold a v0.16 default that changed in v1: keep every v0.16 default, adopt every v1 default, or follow the recommendation per setting |

When every question has an answer, `prepare` prints a summary with the number of objects to write, the objects dropped, warnings and errors. With an external blob store and the `spam_model` category, the summary also states that the final run overwrites the spam models in that blob store (see [Shared blob stores](#shared-blob-stores)). After confirmation it writes two files into the state directory:

- `answers.toml`, the decisions, which later runs read without asking. It can be edited by hand. The changed defaults answer also takes an `overrides` table, which `prepare` never asks for, mapping an object type and setting to `"pin"` (keep the v0.16 default) or `"inherit"` (adopt the v1 default), for example `overrides = { "x:SpamPyzor.enable" = "inherit" }`. The settings concerned are the changes marked `changed default pinned` or `replaced by the new default` in `prepare-report.txt`.
- `prepare-report.txt`, the plan: the summary, every dropped object and every change applied to the settings.

`run` refuses to start while a question is unanswered, so `prepare` must be run again when a later change to the v0.16 settings raises a new question. Without a terminal, for example in a CI job or after editing `answers.toml`, `prepare --non-interactive` validates the existing answers, prints the summary and writes the report; it exits with status 1 while questions remain open.

## Migrating with downtime

When a maintenance window long enough for a complete copy is available, the migration is a single final run:

1. Upgrade the deployment to v0.16.27 if necessary, then run `prepare` as described above.

2. Create the new v1 store (an empty database, cluster or directory) and its configuration file.

3. Stop every v0.16 node.

4. Run the final copy:

   ```sh
   stalwart-migrate run --final \
     --source /etc/stalwart/config.json \
     --target /etc/stalwart-v1/config.json \
     --state /var/lib/stalwart-migrate
   ```

   The command asks the operator to type `yes` to confirm that v0.16 is stopped, or `--yes` confirms in advance when no terminal is attached. It then watches the v0.16 change counters for 30 seconds and stops if they move.

5. Check the result printed at the end of the run and review the report. A final run that completes writes `final-report.txt` into the state directory, with the errors, the warnings (dropped, truncated, clamped, skipped and changed items) and the verification mismatches, and prints a cutover checklist (see [Reading the report](#reading-the-report)).

6. Start the v1 server with the target configuration.

The final run performs the whole migration: it copies every account, copies the final-run categories, finalizes the v1 store, verifies a sample of the accounts, and marks the migration as done. Finalizing recalculates quotas, schedules calendar alarms, queues every copied object for search indexing, records one synthetic change per DAV collection so that clients fetch the new entity tags, and checks that every v1 counter is at least its v0.16 value. `--verify-full` replaces the sample with a complete comparison, which takes as long as reading both stores again.

## Migrating with minimal downtime

For large deployments the bulk of the copy runs while v0.16 keeps serving users, and the downtime covers only the last changes:

1. Run `prepare`, then create the empty v1 store and its configuration file.

2. Start the first full copy with v0.16 running:

   ```sh
   stalwart-migrate run \
     --source /etc/stalwart/config.json \
     --target /etc/stalwart-v1/config.json \
     --state /var/lib/stalwart-migrate
   ```

   This run copies every account and can take hours or days on a large deployment. It can be interrupted at any time and resumed by running the same command again. `--max-ops-per-sec` limits the load it places on the live server.

3. Repeat the same command as often as needed. Each incremental run reads the change log of every account and copies only what changed since the previous run, including settings, new accounts and deleted ones. An account whose change log v0.16 has already purged past the last copied position is copied in full again. Running incremental runs close to the switch keeps the final delta small.

4. At the start of the maintenance window, stop every v0.16 node.

5. Run the final copy:

   ```sh
   stalwart-migrate run --final \
     --source /etc/stalwart/config.json \
     --target /etc/stalwart-v1/config.json \
     --state /var/lib/stalwart-migrate
   ```

   As in a one-shot migration, the final run asks for confirmation, waits 30 seconds to make sure v0.16 is stopped, copies the last changes and the final-run categories, finalizes the store and verifies a sample of accounts.

6. Optionally verify every account before starting v1:

   ```sh
   stalwart-migrate verify --full \
     --source /etc/stalwart/config.json \
     --target /etc/stalwart-v1/config.json \
     --state /var/lib/stalwart-migrate
   ```

7. Start the v1 server with the target configuration.

Once the final run has completed, later runs refuse to write, because v1 may already be serving users from the target. `--force-after-final` overrides this for the case where v1 has not been started yet and a further copy is needed. It must not be used once v1 serves users from the target. A forced run removes the done mark, so `run --final` must complete again before v1 is started.

When the final run reports errors or its verification fails, the migration is not marked as done. The run prints the reason, and repeating `run --final` after fixing the cause resumes where it stopped, because finalizing is itself resumable. When the remaining errors are acceptable losses, `--allow-errors` finalizes anyway and records the accepted errors, which later verifications then take into account.

## Shared blob stores

When v0.16 keeps message bodies, attachments and files in an external blob store, v1 can read the same blobs under the same keys, so the recommended answer in `prepare` is to reuse the store. The tool then copies no blob contents: it writes only the data store entries that link each object to its blob. This saves both time and the storage of a second copy.

The tool never deletes or modifies anything in a blob store that v0.16 uses. In a shared store it only adds new keys: sieve scripts, which v1 stores in a different form, and blobs copied in copy mode, which are written under content-addressed keys that already describe the same bytes.

The learned spam filter models are the only exception. v0.16 and v1 store the classifier and trainer models under the same fixed keys but in incompatible formats, so v1 cannot read the v0.16 model and the reverse. For this reason the `spam_model` category is copied only at the very end of `run --final`: after finalizing, after the verification has passed, and immediately before the migration is marked done, with v0.16 stopped. At that point the tool writes the converted model over the v0.16 model in the shared store, or deletes a model kind that the source does not have. Incremental runs, and final runs that fail or do not finalize, never touch these keys. The overwrite is recorded in the run report and announced in the `prepare` summary. Excluding `spam_model` leaves the v0.16 model in place, which v1 cannot load; deleting the two keys (`STALWART_SPAM_CLASSIFIER_MODEL.lz4` and `STALWART_SPAM_TRAIN_DATA.lz4`) lets v1 train a new model from the spam training samples.

Once v1 runs on a shared blob store, the original v0.16 store is no longer a safe fallback. v1 deletes blobs that it no longer references, including blobs that the stale v0.16 store still links to, and the spam model keys now hold the v1 format. Returning to v0.16 after the switch therefore goes through [`rollback`](#rolling-back-to-v016) into a new store.

When the v0.16 blobs are stored in the data store itself, they are always copied, even if `prepare` recorded the reuse answer, and the run logs a warning to that effect.

## Verifying a migration

`verify` compares the v0.16 and v1 stores through the same record layer that the copy uses, so differences that the migration made deliberately (and reported) are not counted as mismatches:

```sh
stalwart-migrate verify \
  --source /etc/stalwart/config.json \
  --target /etc/stalwart-v1/config.json \
  --state /var/lib/stalwart-migrate
```

By default it checks a sample: `--sample` sets the percentage of accounts (1 by default), to which every account changed since the last run is added, with a minimum of 16 accounts. `--full` checks every account and every row of every change log; the two options are mutually exclusive.

For each checked account the comparison covers the settings, the set of objects in every collection, the fields of mailboxes, emails, calendars, contacts, files and sieve scripts, the last change of every change log, and the counters for document ids, UIDs and changes. Calendar and contact data is compared after parsing, so equivalent iCalendar and vCard texts are equal. The presence of every email and file blob in the target is checked, but the blob contents are not read again.

The command prints a summary line such as:

```text
verify: 120 accounts checked, 0 mismatches, 0 not explained by earlier reports (ok)
```

Every mismatch is written to the report with severity `verify`, and the command exits with status 1 when a mismatch is not explained by an earlier report row. Verification against a running v0.16 server reports the changes made since the last run as mismatches, so a meaningful result requires v0.16 to be stopped and the final run to have completed. `run --final` and `rollback` run the same verification automatically.

## Interruptions and repeated runs

Every run can be interrupted and repeated. The tool records progress only after the corresponding write to the target has been committed, and every write uses the original identifiers, so repeating a batch overwrites identical data and never creates duplicates. After a crash, a power failure or a killed process, running the same command with the same state directory resumes from the last recorded position; the interrupted run is listed as `interrupted` in `status`.

The first SIGINT or SIGTERM (for example from `docker stop` or Kubernetes) asks the tool to finish the batches in progress, flush its state and exit. A second signal exits immediately, which is still safe. Transient errors such as serialization conflicts, lost connections and S3 throttling are retried with exponential backoff; `--retry-attempts` and `--retry-budget` bound the retries of each batch. A batch that exceeds the transaction limits of the target is split in half and retried, down to single objects. A single batch write that does not finish within 15 minutes, or 1 second per MB of the batch when that is longer (an unresponsive target store, or a connection pool that never hands out a connection) fails its account with an error instead of stalling the run; the account is copied again by the next run.

An object that cannot be converted, such as an unparseable message or an invalid calendar event, never stops its account: it is skipped or repaired according to a documented fallback and reported. An account that fails as a whole is marked in error and retried by the next run, while the others continue.

## Selecting data categories

The categories chosen in `prepare` apply to every run. `--include` and `--exclude` override them for a single run, with comma-separated category names:

```sh
stalwart-migrate run --exclude files,telemetry \
  --source /etc/stalwart/config.json \
  --target /etc/stalwart-v1/config.json \
  --state /var/lib/stalwart-migrate
```

Copying the queue in the final run hands every queued message, with its due times and recipient states, over to v1, which then continues the delivery. Changing the categories between runs makes the tool log `data categories changed since the previous run; newly included categories are copied for every account by this run, and data of excluded categories stays in the target as last copied`. A category included later is copied for every account by the next run; an excluded one is no longer updated, but what was already copied stays in the target.

### Mass-removal guard

When an account or a setting disappears from v0.16, the next run deletes it from the target. A source configuration that points at the wrong store, or a store that reads as empty, would otherwise wipe the copy, so the tool holds back large removals. Account removals are held when the source lists no accounts, or when at least 10 accounts and more than 10% of the tracked ones would be removed. Setting removals are held per object type under the same threshold, and whenever the source lists no accounts, domains or tenants while some are tracked. A held removal is reported as an error, for example:

```text
the source lists 250 fewer accounts than the state database (1200 tracked); not wiping them. Check the source configuration or pass --allow-mass-removal
```

The run then fails and `run --final` refuses to finalize. When the removals are intended, `--allow-mass-removal` applies them.

## Dropped and changed data

The run report lists every difference between what v0.16 held and what v1 received. Some data has no place in v1 or exceeds a v1 limit, and some settings change meaning. The conversion handles each case with a documented fallback and records it, so nothing is lost silently. Each report row has a severity and a kind:

| Kind | Meaning |
|---|---|
| `dropped` | The object or field has no v1 equivalent and was not copied. |
| `changed` | The value was converted to a different v1 form. |
| `truncated` | A list or text exceeded a v1 limit and was shortened. |
| `clamped` | A number was outside the v1 range and was set to the nearest allowed value. |
| `skipped` | The object could not be read or converted and was not copied. |
| `failed` | The write to the target failed. |
| `mismatch` | Verification found a difference. |

Severities are `info`, `warning`, `error` and `verify`. Error rows make a run fail and stop `run --final` from finalizing until they are fixed or accepted with `--allow-errors`. The schema differences behind the settings conversions are listed in [SCHEMA_CHANGES.md](SCHEMA_CHANGES.md).

Two conversions go beyond renaming settings:

- **Spam filter tags.** v1 imports the stock spam filter rules only into a store that holds no spam rules, so a migrated deployment keeps the tags of the rules release it imported under v0.16. The conversion renames `DISPOSABLE_REPLYTO` to `DISPOSABLE_REPLY_TO`, the tag the server emits, and drops the `LLM_*` tags, which v1 replaces with the `AI_*` tags of its AI classifier. The final run then adds every stock tag of the current rules that the settings lack (the `AI_*`, `DKIM2_*`, `MIME_LIMIT_EXCEEDED`, `URL_REDIRECTOR_INSECURE`, `DISPOSABLE_BCC` and `FREEMAIL_BCC` tags) with its stock score, and reports each one. Tags that already exist keep their scores, and spam rules, DNSBL servers and lookups stay as migrated.
- **Web interface.** v1 serves only version 2 of the web interface. An application that downloads an official version 1 bundle is pointed to the version 2 bundle, and an application with a custom bundle URL keeps it with a warning, since a custom build of an older web interface is not served.

## Rolling back to v0.16

`rollback` copies a v1 store into a new, empty v0.16 store. It exists for the case where v1 has already served users and the deployment must return to v0.16 without losing the mail, events and files written since the switch. Before v1 has been started, rolling back needs no tool: the v0.16 store was never modified, so restarting v0.16 on it is enough. With a shared blob store this holds only while the v0.16 spam models are still in place, which is no longer the case once a final run with the `spam_model` category has completed (see [Shared blob stores](#shared-blob-stores)).

The rollback is a one-shot copy, run with the v1 server stopped. It never writes into the original v0.16 store, which may be stale and, with a shared blob store, may already miss blobs. The target must therefore be a new, empty v0.16 store, and the rollback needs its own new state directory:

1. Stop every v1 node.

2. Create a new, empty store for v0.16 and a v0.16 configuration file that points to it.

3. Run the rollback, naming the v1 configuration as the source and the new v0.16 configuration as the target:

   ```sh
   stalwart-migrate rollback \
     --source /etc/stalwart-v1/config.json \
     --target /etc/stalwart-rollback/config.json \
     --state /var/lib/stalwart-rollback \
     --forward-state /var/lib/stalwart-migrate
   ```

4. Review the result and the report (`stalwart-migrate report --state /var/lib/stalwart-rollback`).

5. Start v0.16.27 with the new configuration.

Like a final run, the rollback watches the v1 change counters for 30 seconds before it writes and stops if they move. It copies the default categories, preserves account, document and thread ids, UIDs and UIDVALIDITY, verifies a sample of accounts at the end and marks the rollback as done; a completed rollback is not run again. An interrupted rollback resumes when the same command is repeated with the same `--state`.

The options decide how much of the original state can be restored and how far the rollback may reach outside the new store:

| Option | Effect |
|---|---|
| `--forward-state <DIR>` | Reads the state directory of the forward migration. Settings that v1 did not change since the migration are restored with their exact original v0.16 values, and settings that the migration dropped or could not write are restored from their original form. Without it, every setting is converted back from its v1 form and dropped settings are lost. |
| `--allow-shared-deletes` | Allows changes to services shared with v1, chiefly the blob store: overwriting and deleting entries the rollback would otherwise leave in place, and writing the v0.16 spam models back over the v1 models in a shared blob store. Without it, the rollback writes only into the new store and content-addressed blob keys and skips the rest with a warning. |
| `--keep-v1-spam-model` | In a shared blob store, leaves the v1 spam models in place instead of writing the v0.16 models back. v0.16 fails to start while it finds the v1 format under its keys, so the two keys (`STALWART_SPAM_CLASSIFIER_MODEL.lz4` and `STALWART_SPAM_TRAIN_DATA.lz4`) must be deleted before v0.16 starts; it then trains a new model. Cannot be combined with `--allow-shared-deletes`. |
| `--yes` | Confirms in advance that every v1 node is stopped, when no terminal is attached. |
| `--allow-errors` | Completes the rollback even when objects could not be copied, accepting them as losses. |
| `--allow-mass-removal` | Applies removals held by the [mass-removal guard](#mass-removal-guard). |
| `--verify-full` | Verifies every account at the end instead of a sample. |
| `--owner <UID:GID>` | Sets the owner of the files the rollback creates. |
| `--path-map <FROM=TO>` | Rewrites path prefixes in the v1 source configuration. |

The rollback asks the operator to type `yes` to confirm that v1 is stopped, like `run --final`. Before copying anything, it prints what it would delete or overwrite outside the new v0.16 store, and whether `--allow-shared-deletes` permits it. When the new v0.16 store shares its blob store with v1, the spam model keys hold the v1 format, which v0.16 cannot load, so the rollback refuses to start until one of `--allow-shared-deletes` (write the v0.16 models back) or `--keep-v1-spam-model` (keep the v1 models) is given.

Some data is not rolled back. Queued messages, the outbound DMARC and TLS report aggregation, scheduled tasks and telemetry stay with v1, which keeps delivering what is queued in it. A held or pending email submission comes back to v0.16 as sent, because the message itself stays in the v1 queue; let the v1 queue drain before stopping v1 for the rollback. The rollback states this in its output and records it as a warning. Data that exists only in v1 is dropped and reported: v1-only settings and objects, private metadata, per-instance event data such as colours, keywords and alerts, direct calendar notifications, file symlinks, and similar fields with no v0.16 equivalent. Changelogs are copied back where v0.16 can encode them, and DAV clients fetch their data once more after the rollback.

## Migrating CLI plans

Deployments managed as code with `stalwart-cli` keep their settings in plans, the NDJSON files read by `stalwart-cli apply` and written by `stalwart-cli snapshot`. A plan written for v0.16 uses the v0.16 schema, which v1 rejects. `cli-plan/convert_plan.py` converts it to the v1 schema with the same mapping rules and questions that `stalwart-migrate` applies to the settings it copies.

Plans are converted separately from the data migration. The migrated v1 store already holds the converted settings, so a converted plan is needed only to keep managing the v1 deployment with plans, or to set up a new v1 server from one.

The converter is not part of the release archives or the Docker image. It requires Python 3.11 or later and no other modules, and it runs from a checkout of this repository at the tag of the release, because it reads the schema snapshots and mapping rules in `mapping/`:

```sh
git clone --depth 1 --branch v1.0.3 https://github.com/stalwartlabs/stalwart-migrate.git
cd stalwart-migrate
```

A plan is converted in three steps:

1. Answer the questions the plan raises. `prepare` is interactive and needs a terminal:

   ```sh
   python3 cli-plan/convert_plan.py prepare plan.ndjson --answers plan.answers.toml
   ```

2. Convert the plan:

   ```sh
   python3 cli-plan/convert_plan.py convert plan.ndjson -o plan-v1.ndjson \
     --answers plan.answers.toml --report plan-v1-report.txt
   ```

3. Review the report, then check the converted plan offline and against the v1 server before applying it:

   ```sh
   python3 cli-plan/convert_plan.py validate plan-v1.ndjson
   stalwart-cli --url https://mail.example.org apply --file plan-v1.ndjson --dry-run
   stalwart-cli --url https://mail.example.org apply --file plan-v1.ndjson
   ```

The questions are those of [Preparing the migration](#preparing-the-migration), asked for the plan entries they concern; the questions about blob stores and data categories do not apply to plans. The answers file has the format of the `answers.toml` written by `stalwart-migrate prepare`, and answers that do not name an object, such as the handling of changed defaults and new permissions, apply to both. Answers about a single object are keyed differently, though: by the object id in the state directory, and by the client id of the plan entry in a plan. Because `convert` rewrites the answers file, a copy of the state directory's `answers.toml` is the right starting point, never the file itself.

Plans for a Stalwart server compiled without the `enterprise` feature are converted against the open-source schema. To select it, add the following to the answers file and validate with `validate --oss`:

```toml
[global.edition]
edition = "oss"
```

The conversion keeps the order of the plan entries and their client ids, and also accepts plans written for earlier 0.16 releases. A plan that already uses the v1 schema is copied unchanged. Some cases need attention:

- Without `--answers`, `prepare` uses `<plan>.answers.toml` and `convert` uses `<output>.answers.toml`, so both steps must be given the same `--answers`.
- When no terminal is attached, `convert` applies the recommended answer to every open question and lists each one as `default applied:` in the report. `--strict` makes it refuse instead, which suits unattended runs.
- Entries whose content has no v1 equivalent are dropped, and an entry left empty is removed from the plan. References to a dropped entry are cleared where the field allows it and reported as errors otherwise. Check that every entry still comes after the entries it references.
- Secrets that `stalwart-cli snapshot` masked as `****` stay masked and are reported as warnings; set them on the v1 server after applying. Secrets present in the plan are copied in clear, and secrets given as answers are stored in clear in the answers file, which is created readable only by its owner.
- The annotation lines starting with `#` in the `stalwart-cli` documentation are not valid NDJSON and must be removed before converting.

Each report line has the form `<level>: <object> [<property>]: <text>`, with level `info`, `warning` or `error`. The report lists every dropped value with its original content (secrets masked), every clamped number, every conversion of a changed setting, and the defaults applied to open questions. Without `--report`, it is printed on standard error. `convert` exits with status 0 when the plan was converted without issues. It exits with status 1 when the converted plan was written but has validation issues or references it could not clear, and with status 2 when it refused to convert: an invalid plan or answers file, open questions with `--strict`, or an answer that stops the conversion.

## Performance tuning

Throughput depends mostly on the target backend and on how many accounts are copied at once. These options adjust the copy for `run`, `verify` and `rollback`:

| Option | Effect |
|---|---|
| `--concurrency <N>` | Number of write slots (4 per CPU by default): the maximum number of accounts copied at once, and of batches being written at once. Within an account, collections are copied one after another. |
| `--account-split <N>` | Maximum number of write slots one account may use at once for its emails (default 8). An account only takes extra slots that no waiting account needs. `1` copies every account with a single writer. |
| `--batch-ops <N>` | Maximum operations per target transaction (default 1000). |
| `--batch-bytes <N>` | Maximum bytes per target transaction (default 5242880). |
| `--fdb-txn-bytes <N>` | Maximum bytes per FoundationDB transaction (default 2097152), which keeps transactions well under the FoundationDB size and time limits. |
| `--blob-concurrency <N>` | Number of blobs copied in parallel when blobs are copied (default: the number of write slots, at least 16). |
| `--read-ahead <N>` | Number of batches read ahead of the writes for each account (default 2). |
| `--max-ops-per-sec <N>` | Global rate limit, which protects a live v0.16 server during incremental runs. |
| `--retry-attempts <N>`, `--retry-budget <SECONDS>` | Retry limits for each batch (defaults 10 attempts and 300 seconds). |

Accounts with the most pending changes are copied first, so large mailboxes start at the beginning of a run instead of finishing alone at its end. Once fewer accounts than write slots are left, the remaining large accounts write their emails through the idle slots, up to `--account-split` each. Other collections of an account, such as calendars, contacts and files, are still written by one writer per account. `run` and `rollback` print a progress line every 15 seconds, `--progress-interval` changes the interval, and 0 disables it.

## Paths and file ownership

The tool reads the paths in the configuration files and in the v0.16 registry (a RocksDB directory, a SQLite file, a file system blob store, a FoundationDB cluster file) exactly as the servers see them. When the tool runs on a host where those paths differ, for example against the volumes of a Docker deployment, `--path-map` rewrites path prefixes on the v0.16 side and `--target-path-map` on the v1 side; both can be given several times:

```sh
stalwart-migrate run \
  --source ./v016/config.json \
  --target ./v1/config.json \
  --state /var/lib/stalwart-migrate \
  --path-map /var/lib/stalwart=/srv/docker/stalwart/data \
  --target-path-map /var/lib/stalwart-v1=/srv/docker/stalwart-v1/data \
  --owner 2000:2000
```

`--owner` changes the owner of the files and directories the tool creates for the target, which matters when the tool runs as root and the v1 server (such as the official container image, which runs as uid 2000) runs as another user. Running as root without `--owner` produces a warning before any target file is created.

`prepare` needs a terminal, so in containers it is run with one attached (`docker run -it`, `docker compose run`, `kubectl run -it` or `kubectl exec -it`).

## Known limitations

- A SQLite source on NFS, or opened through hard links, is not supported while v0.16 is running. SQLite locking is unreliable over NFS, and the tool detects a running server by the paths of the database and its write-ahead log.
- Pending v0.16 thread merges are not copied. Conversations that v0.16 was about to merge stay split in v1, and the final run reports one warning per account with the number of pending merges.
- Only emails are written with several slots per account; the other collections of a very large account are copied by a single writer, as described in [Performance tuning](#performance-tuning).
- Verification checks that every email and file blob exists in the target but does not compare blob contents.
- v0.16 does not record when a scheduled task that is being retried first failed. The copied task keeps its retry state and uses the time the task was created as its first failure.
- v0.16 stores a trace when it ends, under an identifier taken when it started, so each run reads traces again from six hours before the newest trace it has seen and copies the ones it has not seen yet. A trace that v0.16 stores more than six hours after it started is not copied, and the verification after the final run reports it as missing. Metrics are read again from ten minutes back for the same reason.
- Copied metrics are stored as written by node 0. v0.16 records the writing node in the metric identifier, but the v1 cluster may number its nodes differently.
- The tool runs on Unix-like systems.

## Reading the report

### Status

`status` summarises a state directory without opening any store, so it can run while another command is in progress:

```sh
stalwart-migrate status --state /var/lib/stalwart-migrate
```

It shows the recorded metadata (tool version and build, whether the final run is done), the number of accounts in each phase, the accounts in error with their last error, the recent runs with their duration and counters, and the report counts by severity and kind for the latest run and for all runs. `--format json` produces the same data for monitoring.

### Report

`report` lists the individual report rows:

```sh
stalwart-migrate report --state /var/lib/stalwart-migrate --severity error
stalwart-migrate report --state /var/lib/stalwart-migrate --run 7 --format csv > run7.csv
stalwart-migrate report --state /var/lib/stalwart-migrate --account 42 --category truncated
```

The rows can be filtered by run (`--run`), severity (`--severity`: `info`, `warning`, `error`, `verify`), kind (`--category`), account id (`--account`) and number of rows (`--limit`), and printed as text, CSV or JSON (`--format`). The rows of the final run, and those with severity `error` and `verify`, are the ones to review before the switch.

### State directory

The state directory contains:

| Path | Content |
|---|---|
| `answers.toml` | The answers recorded by `prepare`. |
| `prepare-report.txt` | The settings conversion plan written by `prepare`. |
| `state.sqlite` | Progress, runs and report rows. |
| `state.lock` | Lock that prevents two commands from writing the same state at once. |
| `logs/` | One log file per command, named after the command, the start time and the process id. |

The state files are created readable only by their owner, because `answers.toml` and the state database may contain secrets from the v0.16 settings. `--log-format` selects text or JSON console output, and `--log-level` sets the verbosity.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The command succeeded. |
| 1 | The command failed: a run that failed or reported errors, a verification with unexplained mismatches, `prepare` with open questions, or an error opening a store. |
| 2 | Invalid usage or a refusal before any work: wrong arguments, a missing `answers.toml`, an unconfirmed final run, a tool build that does not match the recorded answers. |
| 130 | The command was interrupted by a signal. |

## Troubleshooting

Most refusals protect the v0.16 data or the integrity of the copy, and are reported with these messages:

| Message | Cause and resolution |
|---|---|
| `the target store is not empty; the first run requires an empty target` | The first run found data in the target. Create a new, empty store. |
| `the v1 target is an existing store that this tool did not create; ...` | The target database holds tables or a store that another installation created. Use a new database; on PostgreSQL, other schemas must not be on the connecting user's search path. |
| `the v1 --target already holds a v1 store that this --state did not create; ...` | The target was filled by another migration. Use the state directory of that migration or a new store. |
| `another state directory has used this target since this one last ran; ...` | A different state directory, or a backup or copy of this one, ran against the target after this state last did. Use the state directory that ran last. A state directory restored from a backup or copied cannot continue: start again with a new `--state` directory and a new, empty target. |
| `the target store is empty but the state database records earlier progress; use a new --state directory` | The target was recreated after earlier runs. Start again with a new state directory. |
| `the --state directory <dir> overlaps the <store> <path>; keep the state outside every store` | The state directory lies inside or around a data store or file system blob store. Move it elsewhere. |
| `the target store <path> overlaps the source <store> <path>; the target must be a separate, new location` | The v1 target shares a location with the v0.16 data or blob store. Choose a separate path. |
| `source change counters moved during the 30 second observation window; stop every v0.16 node before run --final` | A v0.16 node is still running. Stop every node and repeat the final run. |
| `a v0.16 server started on the SQLite source <path> after it was opened; stop every v0.16 server and rerun` | v0.16 was started during a run against a SQLite store. Stop it and repeat the command. |
| `run --final needs an interactive confirmation; pass --yes when no terminal is attached` | The final run was started without a terminal. Add `--yes` once v0.16 is stopped. |
| `the final run has already completed and v1 may be live; use --force-after-final to write anyway` | The migration is done. Do not write again unless v1 has not been started. |
| `<dir>/answers.toml not found; run prepare first` | `prepare` has not been run with this state directory. |
| `prepare is interactive and needs a terminal. ...` | Attach a terminal, or use `prepare --non-interactive` to validate an existing `answers.toml`. |
| `answers.toml selects the <edition> edition but this binary is the <edition> edition` | The answers were recorded by an earlier version for the other build of the tool. Install the build that matches the Stalwart server, as described in [Installation](#installation). |
| `the <side> store definition differs from the one recorded in the state database` | `--source` or `--target` changed since the previous run. Use the original files, or a new state directory and target. |
| `not finalizing: accounts are in error (use --allow-errors to finalize anyway)` | Some accounts failed. Check `status` and `report --severity error`, fix the cause and repeat, or accept the losses with `--allow-errors`. |
| `the source lists <n> fewer accounts than the state database (<m> tracked); ...` | The mass-removal guard held the removals. Check the source configuration, or pass `--allow-mass-removal` if the removals are intended. |
| `the <side> store path <path> is a SQLite URI; use a plain file system path` | SQLite stores must be given as file paths. |
| `the v0.16 rollback target <path> already exists; rollback writes into a new, empty location only` | The rollback target must be new. |
| `the rollback --source is a v0.16 store; rollback reads the migrated v1 store` | The rollback source must be the v1 store. |

## Building from source

Most deployments use the prebuilt binaries or the Docker image described in [Installation](#installation). Building from source is needed only for a platform or a combination of features that is not published.

The tool compiles against patched copies of the parts of the Stalwart v0.16.27 and v1 sources it uses, which are included in `vendor/`. The build requires Rust 1.98 or later, a C and C++ compiler and libclang.

```sh
git clone https://github.com/stalwartlabs/stalwart-migrate.git
cd stalwart-migrate
cargo build --release -p migrate --features sqlite,postgres,mysql,s3,azure,redis
```

The binary is written to `target/release/stalwart-migrate`. RocksDB support is built by default, and the other backends are enabled with Cargo features:

| Feature | Enables |
|---|---|
| `rocks` | RocksDB (default) |
| `sqlite` | SQLite |
| `postgres` | PostgreSQL |
| `mysql` | MySQL |
| `foundation` | FoundationDB. Requires the FoundationDB client library on the build host and on the host that runs the tool. |
| `s3` | S3 and S3-compatible blob stores |
| `azure` | Azure Blob Storage |
| `redis` | Redis |
| `enterprise` | Support for the features of a Stalwart server built with the `enterprise` feature (default) |

The tool must be built with every backend that the v0.16 configuration and the v1 target refer to, including the blob store. A tool for a Stalwart server compiled without the `enterprise` feature is built without it as well, for example with `cargo build --release -p migrate --no-default-features --features rocks,sqlite,postgres`.

## License

This project is dual-licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0; as published by the Free Software Foundation) OR the **Stalwart Enterprise License v2 (SELv2)**:

- The [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0) is a free software license that ensures the freedom to use, modify, and distribute the software, with the condition that any modified versions of the software must also be distributed under the same license.
- The Stalwart Enterprise License v2 (SELv2) is a proprietary license designed for commercial use. It offers additional features and greater flexibility for businesses that do not wish to comply with the AGPL-3.0 license requirements.

Each file in this project contains a license notice at the top, indicating the applicable license(s). The license notice follows the [REUSE guidelines](https://reuse.software/) to ensure clarity and consistency.

## Copyright

Copyright (C) 2020, Stalwart Labs LLC
