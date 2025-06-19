// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, time::Duration};

use axum::{http::StatusCode, routing::get, Extension, Router};
use prometheus::{
    register_histogram_vec_with_registry,
    register_int_gauge_with_registry,
    HistogramVec,
    IntGauge,
    Registry,
    TextEncoder,
};
use tokio::{net::TcpListener, task::JoinHandle};

const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.1, 0.25, 0.5, 0.75, 1., 1.25, 1.5, 1.75, 2., 2.5, 3.0, 4.0, 5., 10., 20., 30., 60., 90.,
];

pub const METRICS_ROUTE: &str = "/metrics";

pub const TOTAL_LATENCY_S: &str = "total_latency_s";
pub const PROVERS_LATENCY_S: &str = "provers_latency_s";
pub const PW_BUILDER_LABEL: &str = "pw_builder";
pub const BASIC_PROVER_LABEL: &str = "basic_prover";
pub const COMPRESS_PROVER_LABEL: &str = "compress_prover";
pub const CYCLIC_PROVER_LABEL: &str = "cyclic_prover";
pub const UPDATES_IN_FLIGHT: &str = "updates_in_flight";

pub fn start_prometheus_server(
    address: SocketAddr,
    registry: &Registry,
) -> JoinHandle<Result<(), std::io::Error>> {
    let app = Router::new()
        .route(METRICS_ROUTE, get(metrics_route))
        .layer(Extension(registry.clone()));

    tracing::info!("Prometheus server booted on {address}");
    tokio::spawn(async move {
        let listener = TcpListener::bind(address).await?;
        axum::serve(listener, app).await?;
        Ok(())
    })
}

async fn metrics_route(registry: Extension<Registry>) -> (StatusCode, String) {
    let metrics_families = registry.gather();
    match TextEncoder.encode_to_string(&metrics_families) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to encode metrics: {error}"),
        ),
    }
}

pub struct Metrics {
    total_latency_s: HistogramVec,
    provers_latency_s: HistogramVec,
    updates_in_flight: IntGauge,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            total_latency_s: register_histogram_vec_with_registry!(
                TOTAL_LATENCY_S,
                "Buckets measuring end-to-end latency in seconds",
                &["workload"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            provers_latency_s: register_histogram_vec_with_registry!(
                PROVERS_LATENCY_S,
                "Buckets measuring the latency of a prover in seconds",
                &["prover"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            updates_in_flight: register_int_gauge_with_registry!(
                UPDATES_IN_FLIGHT,
                "Number of state updates currently being processed",
                registry,
            )
            .unwrap(),
        }
    }

    pub fn observe_total_latency(&self, workload: &str, duration: Duration) {
        tracing::debug!("Total latency for workload '{workload}' is {duration:?}");
        self.total_latency_s
            .with_label_values(&[workload])
            .observe(duration.as_secs_f64());
    }

    fn observe_prover_latency(&self, prover: &str, duration: Duration) {
        self.provers_latency_s
            .with_label_values(&[prover])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_partial_witness_builder_latency(&self, duration: Duration) {
        tracing::debug!("Partial witness built in {:?}", duration);
        self.observe_prover_latency(PW_BUILDER_LABEL, duration);
    }

    pub fn observe_basic_prover_latency(&self, duration: Duration) {
        tracing::debug!("Basic prover completed in {:?}", duration);
        self.observe_prover_latency(BASIC_PROVER_LABEL, duration);
    }

    pub fn observe_compress_prover_latency(&self, duration: Duration) {
        tracing::debug!("Compress prover completed in {:?}", duration);
        self.observe_prover_latency(COMPRESS_PROVER_LABEL, duration);
    }

    pub fn observe_cyclic_prover_latency(&self, duration: Duration) {
        tracing::debug!("Cyclic prover completed in {:?}", duration);
        self.observe_prover_latency(CYCLIC_PROVER_LABEL, duration);
    }

    pub fn new_state_updates(&self, count: usize) {
        tracing::debug!("New state updates received: {count}");
        self.updates_in_flight.add(count as i64);
    }

    pub fn state_updates_completed(&self, count: usize) {
        tracing::debug!("State updates completed: {count}");
        self.updates_in_flight.sub(count as i64);
    }
}
