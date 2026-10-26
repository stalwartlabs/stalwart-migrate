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
use model::{TargetClaim, TargetProbe};
use registry::schema::structs::DataStore;
use store::{RegistryStore, Store, registry::bootstrap::Bootstrap};

use crate::{
    claim::recover_sqlite,
    error::fatal,
    owned::OwnedPaths,
    paths::{PathRewrite, boot_rewrite, primary_only, rewrite_data_store},
    precheck::{probe_definition, refuse_foreign_store},
};

pub struct TargetConfig {
    pub data_store: PathBuf,
    pub fdb_txn_bytes: u64,
}

pub struct V1Target {
    pub(crate) registry: RegistryStore,
    pub(crate) store: Store,
    server: OnceLock<Server>,
    max_batch_bytes: Option<u64>,
    owned: OwnedPaths,
    path_rewrite: Option<PathRewrite>,
    pub(crate) claim: Option<TargetClaim>,
}

impl V1Target {
    pub async fn open(config: TargetConfig) -> model::Result<Self> {
        Self::open_with_rewrite(config, None).await
    }

    pub async fn probe_store(
        config: &TargetConfig,
        path_rewrite: Option<&PathRewrite>,
    ) -> model::Result<TargetProbe> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let definition = primary_only(read_definition(&config.data_store)?);
        let definition = match path_rewrite {
            Some(path_rewrite) => rewrite_data_store(path_rewrite, definition),
            None => definition,
        };
        probe_definition(&definition).await
    }

    pub async fn open_with_rewrite(
        config: TargetConfig,
        path_rewrite: Option<PathRewrite>,
    ) -> model::Result<Self> {
        Self::open_inner(config, path_rewrite, None).await
    }

    pub async fn open_claimed(
        config: TargetConfig,
        path_rewrite: Option<PathRewrite>,
        claim: TargetClaim,
    ) -> model::Result<Self> {
        let target = Self::open_inner(config, path_rewrite, Some(claim)).await?;
        target.check_claim(claim).await?;
        Ok(target)
    }

    async fn open_inner(
        config: TargetConfig,
        path_rewrite: Option<PathRewrite>,
        claim: Option<TargetClaim>,
    ) -> model::Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rewrite = |store: DataStore| match &path_rewrite {
            Some(path_rewrite) => rewrite_data_store(path_rewrite, primary_only(store)),
            None => primary_only(store),
        };
        let definition = rewrite(read_definition(&config.data_store)?);
        if let (Some(TargetClaim::Claimed(id)), DataStore::Sqlite(store)) = (claim, &definition) {
            recover_sqlite(&store.path, id)?;
        }
        refuse_foreign_store(&definition).await?;
        let owned = match &definition {
            DataStore::RocksDb(store) => OwnedPaths::directory(Path::new(&store.path)),
            DataStore::Sqlite(store) => OwnedPaths::file(Path::new(&store.path)),
            _ => OwnedPaths::None,
        };
        let max_batch_bytes =
            matches!(definition, DataStore::FoundationDb(_)).then_some(config.fdb_txn_bytes.max(1));
        let registry = RegistryStore::init_with(config.data_store.clone(), false, rewrite)
            .await
            .map_err(|err| fatal(format!("cannot open the v1 target store: {err}")))?;
        if registry.is_bootstrap_mode() {
            return Err(fatal(
                "the v1 target configuration does not define a data store",
            ));
        }
        let store = registry.store().clone();
        Ok(V1Target {
            registry,
            store,
            server: OnceLock::new(),
            max_batch_bytes,
            owned,
            path_rewrite,
            claim,
        })
    }

    pub fn server(&self) -> model::Result<&Server> {
        self.server
            .get()
            .ok_or_else(|| fatal("the v1 server stage has not been started"))
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn registry(&self) -> &RegistryStore {
        &self.registry
    }

    pub(crate) fn batch_limit(&self) -> Option<u64> {
        self.max_batch_bytes
    }

    pub(crate) fn paths(&self) -> Vec<PathBuf> {
        self.owned.list()
    }

    pub(crate) async fn boot_server(&self) -> model::Result<()> {
        if self.server.get().is_some() {
            return Ok(());
        }
        store::write::compress::init();
        let mut bootstrap = Bootstrap::new(self.registry.clone())
            .await
            .with_object_rewrite(boot_rewrite(self.path_rewrite.clone()));
        let storage = Storage::parse(&mut bootstrap).await;
        let (ipc, receivers) = build_ipc(false);
        drop(receivers);
        let _telemetry = Telemetry::parse(&mut bootstrap, &storage, ipc.index_queue_notify()).await;
        let core = Core::parse(&mut bootstrap, storage).await;
        let data = Data::parse(&mut bootstrap).await;
        let (cache, _swap_rx) = Caches::parse(&mut bootstrap, &core.storage).await;
        if bootstrap.has_fatal_errors {
            return Err(fatal(format!(
                "the migrated v1 settings do not load: {}",
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

fn read_definition(path: &Path) -> model::Result<DataStore> {
    let contents = std::fs::read_to_string(path)
        .map_err(|err| fatal(format!("cannot read {}: {err}", path.display())))?;
    serde_json::from_str::<DataStore>(&contents)
        .map_err(|err| fatal(format!("cannot parse {}: {err}", path.display())))
}
