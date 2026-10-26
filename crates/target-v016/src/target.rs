/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use arc_swap::ArcSwap;
use common::{
    BuildServer, Caches, Core, Data, Inner, Server,
    config::{storage::Storage, telemetry::Telemetry},
    manager::boot::build_ipc,
};
use registry::schema::structs::DataStore;
use store::{RegistryStore, Store, registry::bootstrap::Bootstrap};

use model::{SharedDeletes, TargetClaim};

use crate::{
    claim::recover_sqlite, error::fatal, isolation::boot_rewrite, owned::OwnedPaths,
    precheck::refuse_foreign_store,
};

pub struct TargetConfig {
    pub data_store: PathBuf,
    pub shared_deletes: SharedDeletes,
}

pub struct V016Target {
    pub(crate) registry: RegistryStore,
    pub(crate) store: Store,
    pub(crate) shared_deletes: SharedDeletes,
    server: OnceLock<Server>,
    owned: OwnedPaths,
    pub(crate) claim: Option<TargetClaim>,
}

impl V016Target {
    pub async fn open(config: TargetConfig) -> model::Result<Self> {
        Self::open_inner(config, None).await
    }

    pub async fn open_claimed(config: TargetConfig, claim: TargetClaim) -> model::Result<Self> {
        let target = Self::open_inner(config, Some(claim)).await?;
        target.check_claim(claim).await?;
        Ok(target)
    }

    async fn open_inner(config: TargetConfig, claim: Option<TargetClaim>) -> model::Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let definition = primary_only(read_definition(&config.data_store)?);
        if let (Some(TargetClaim::Claimed(id)), DataStore::Sqlite(store)) = (claim, &definition) {
            recover_sqlite(&store.path, id)?;
        }
        refuse_foreign_store(&definition).await?;
        let owned = match definition {
            DataStore::RocksDb(store) => OwnedPaths::directory(Path::new(&store.path)),
            DataStore::Sqlite(store) => OwnedPaths::file(Path::new(&store.path)),
            DataStore::FoundationDb(_) | DataStore::PostgreSql(_) | DataStore::MySql(_) => {
                OwnedPaths::None
            }
        };
        let registry = RegistryStore::init_with(config.data_store, false, primary_only)
            .await
            .map_err(|err| fatal(format!("cannot open the v0.16 target store: {err}")))?;
        if registry.is_bootstrap_mode() {
            return Err(fatal(
                "the v0.16 target configuration does not define a data store",
            ));
        }
        let store = registry.store().clone();
        Ok(V016Target {
            registry,
            store,
            shared_deletes: config.shared_deletes,
            server: OnceLock::new(),
            owned,
            claim,
        })
    }

    pub fn server(&self) -> model::Result<&Server> {
        self.server
            .get()
            .ok_or_else(|| fatal("the v0.16 server stage has not been started"))
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn registry(&self) -> &RegistryStore {
        &self.registry
    }

    pub fn shared_deletes(&self) -> SharedDeletes {
        self.shared_deletes
    }

    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        self.owned.list()
    }

    pub async fn boot_server(&self) -> model::Result<()> {
        if self.server.get().is_some() {
            return Ok(());
        }
        let mut bootstrap = Bootstrap::new(self.registry.clone())
            .await
            .with_object_rewrite(boot_rewrite(self.shared_deletes));
        let storage = Storage::parse(&mut bootstrap).await;
        let (ipc, receivers) = build_ipc(false);
        drop(receivers);
        let _telemetry = Telemetry::parse(&mut bootstrap, &storage).await;
        let core = Core::parse(&mut bootstrap, storage).await;
        let data = Data::parse(&mut bootstrap).await;
        let cache = Caches::parse(&mut bootstrap).await;
        if bootstrap.has_fatal_errors {
            return Err(fatal(format!(
                "the v0.16 settings do not load: {}",
                bootstrap
                    .errors
                    .iter()
                    .map(|err| format!("{err:?}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            )));
        }
        let inner = Arc::new(Inner {
            shared_core: ArcSwap::new(Arc::from(core)),
            data,
            ipc,
            cache,
        });
        let _ = self.server.set(inner.build_server());
        Ok(())
    }
}

fn primary_only(mut store: DataStore) -> DataStore {
    match &mut store {
        DataStore::PostgreSql(store) => store.read_replicas = Default::default(),
        DataStore::MySql(store) => store.read_replicas = Default::default(),
        DataStore::RocksDb(_) | DataStore::Sqlite(_) | DataStore::FoundationDb(_) => {}
    }
    store
}

fn read_definition(path: &Path) -> model::Result<DataStore> {
    let contents = std::fs::read_to_string(path)
        .map_err(|err| fatal(format!("cannot read {}: {err}", path.display())))?;
    serde_json::from_str::<DataStore>(&contents)
        .map_err(|err| fatal(format!("cannot parse {}: {err}", path.display())))
}
