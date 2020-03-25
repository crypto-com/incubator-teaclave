// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![cfg_attr(feature = "mesalock_sgx", no_std)]
#[cfg(feature = "mesalock_sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[macro_use]
extern crate log;

use std::prelude::v1::*;
use teaclave_attestation::verifier;
use teaclave_attestation::{AttestationConfig, RemoteAttestation};
use teaclave_binder::proto::{
    ECallCommand, FinalizeEnclaveInput, FinalizeEnclaveOutput, InitEnclaveInput, InitEnclaveOutput,
    StartServiceInput, StartServiceOutput,
};
use teaclave_binder::{handle_ecall, register_ecall_handler};
use teaclave_config::{RuntimeConfig, BUILD_CONFIG};
use teaclave_proto::teaclave_frontend_service::{
    TeaclaveFrontendRequest, TeaclaveFrontendResponse,
};
use teaclave_rpc::config::SgxTrustedTlsServerConfig;
use teaclave_rpc::server::SgxTrustedTlsServer;
use teaclave_service_enclave_utils::{
    create_trusted_authentication_endpoint, create_trusted_management_endpoint, ServiceEnclave,
};
use teaclave_types::{TeeServiceError, TeeServiceResult};

mod service;

const AS_ROOT_CA_CERT: &[u8] = BUILD_CONFIG.as_root_ca_cert;

fn start_service(config: &RuntimeConfig) -> anyhow::Result<()> {
    let listen_address = config.api_endpoints.frontend.listen_address;
    let as_config = &config.attestation;
    let attestation_config = AttestationConfig::new(
        &as_config.algorithm,
        &as_config.url,
        &as_config.key,
        &as_config.spid,
    );
    let attested_tls_config = RemoteAttestation::new()
        .config(attestation_config)
        .generate_and_endorse()
        .unwrap()
        .attested_tls_config()
        .unwrap();
    let server_config =
        SgxTrustedTlsServerConfig::from_attested_tls_config(attested_tls_config).unwrap();

    let mut server = SgxTrustedTlsServer::<TeaclaveFrontendResponse, TeaclaveFrontendRequest>::new(
        listen_address,
        server_config,
    );

    let enclave_info =
        teaclave_types::EnclaveInfo::from_bytes(&config.audit.enclave_info_bytes.as_ref().unwrap());
    let authentication_service_endpoint = create_trusted_authentication_endpoint(
        &config.internal_endpoints.authentication.advertised_address,
        &enclave_info,
        AS_ROOT_CA_CERT,
        verifier::universal_quote_verifier,
    );

    let management_service_endpoint = create_trusted_management_endpoint(
        &config.internal_endpoints.management.advertised_address,
        &enclave_info,
        AS_ROOT_CA_CERT,
        verifier::universal_quote_verifier,
    );

    let service = service::TeaclaveFrontendService::new(
        authentication_service_endpoint,
        management_service_endpoint,
    )?;
    match server.start(service) {
        Ok(_) => (),
        Err(e) => {
            error!("Service exit, error: {}.", e);
        }
    }
    Ok(())
}

#[handle_ecall]
fn handle_start_service(input: &StartServiceInput) -> TeeServiceResult<StartServiceOutput> {
    start_service(&input.config).map_err(|_| TeeServiceError::ServiceError)?;
    Ok(StartServiceOutput)
}

#[handle_ecall]
fn handle_init_enclave(_: &InitEnclaveInput) -> TeeServiceResult<InitEnclaveOutput> {
    ServiceEnclave::init(env!("CARGO_PKG_NAME"))?;
    Ok(InitEnclaveOutput)
}

#[handle_ecall]
fn handle_finalize_enclave(_: &FinalizeEnclaveInput) -> TeeServiceResult<FinalizeEnclaveOutput> {
    ServiceEnclave::finalize()?;
    Ok(FinalizeEnclaveOutput)
}

register_ecall_handler!(
    type ECallCommand,
    (ECallCommand::StartService, StartServiceInput, StartServiceOutput),
    (ECallCommand::InitEnclave, InitEnclaveInput, InitEnclaveOutput),
    (ECallCommand::FinalizeEnclave, FinalizeEnclaveInput, FinalizeEnclaveOutput),
);

#[cfg(feature = "enclave_unit_test")]
pub mod tests {
    use super::*;

    pub fn run_tests() -> bool {}
}
