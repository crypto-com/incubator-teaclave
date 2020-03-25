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

#[cfg(feature = "mesalock_sgx")]
use std::prelude::v1::*;

use crate::teaclave_common_proto as proto;
use anyhow::{bail, Error, Result};
use teaclave_types::{FileCrypto, TaskStatus, TeaclaveFile128Key};

#[derive(Debug)]
pub struct UserCredential {
    pub id: std::string::String,
    pub token: std::string::String,
}

impl UserCredential {
    pub fn new(id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            token: token.into(),
        }
    }
}

impl std::convert::TryFrom<proto::UserCredential> for UserCredential {
    type Error = Error;

    fn try_from(proto: proto::UserCredential) -> Result<Self> {
        let ret = Self {
            id: proto.id,
            token: proto.token,
        };

        Ok(ret)
    }
}

impl From<UserCredential> for proto::UserCredential {
    fn from(request: UserCredential) -> Self {
        Self {
            id: request.id,
            token: request.token,
        }
    }
}

impl std::convert::TryFrom<proto::FileCryptoInfo> for FileCrypto {
    type Error = Error;
    fn try_from(proto: proto::FileCryptoInfo) -> Result<Self> {
        FileCrypto::new(&proto.schema, &proto.key, &proto.iv)
    }
}

impl std::convert::TryFrom<proto::FileCryptoInfo> for TeaclaveFile128Key {
    type Error = Error;
    fn try_from(proto: proto::FileCryptoInfo) -> Result<Self> {
        let file_crypto = FileCrypto::new(&proto.schema, &proto.key, &proto.iv)?;
        let crypto = match file_crypto {
            FileCrypto::TeaclaveFile128(info) => info,
            _ => anyhow::bail!("FileCryptoInfo not supported"),
        };
        Ok(crypto)
    }
}

impl std::convert::From<FileCrypto> for proto::FileCryptoInfo {
    fn from(crypto: FileCrypto) -> Self {
        let (key, iv) = crypto.key_iv();
        proto::FileCryptoInfo {
            schema: crypto.schema().to_owned(),
            key,
            iv,
        }
    }
}

impl std::convert::From<TeaclaveFile128Key> for proto::FileCryptoInfo {
    fn from(crypto: TeaclaveFile128Key) -> Self {
        let crypto = FileCrypto::TeaclaveFile128(crypto);
        let (key, iv) = crypto.key_iv();
        proto::FileCryptoInfo {
            schema: crypto.schema().to_owned(),
            key,
            iv,
        }
    }
}

pub fn i32_to_task_status(status: i32) -> Result<TaskStatus> {
    let ret = match proto::TaskStatus::from_i32(status) {
        Some(proto::TaskStatus::Created) => TaskStatus::Created,
        Some(proto::TaskStatus::Ready) => TaskStatus::Ready,
        Some(proto::TaskStatus::Approved) => TaskStatus::Approved,
        Some(proto::TaskStatus::Running) => TaskStatus::Running,
        Some(proto::TaskStatus::Failed) => TaskStatus::Failed,
        Some(proto::TaskStatus::Finished) => TaskStatus::Finished,
        None => bail!("invalid task status"),
    };
    Ok(ret)
}

pub fn i32_from_task_status(status: TaskStatus) -> i32 {
    match status {
        TaskStatus::Created => proto::TaskStatus::Created as i32,
        TaskStatus::Ready => proto::TaskStatus::Ready as i32,
        TaskStatus::Approved => proto::TaskStatus::Approved as i32,
        TaskStatus::Running => proto::TaskStatus::Running as i32,
        TaskStatus::Failed => proto::TaskStatus::Failed as i32,
        TaskStatus::Finished => proto::TaskStatus::Finished as i32,
    }
}
