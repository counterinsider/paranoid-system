// SPDX-License-Identifier: MIT OR Apache-2.0
//! Helpers for interaction with TPM

use crate::{env::constants::*, log::*};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::engine::{Engine, general_purpose};
use openssl::{
    hash::{Hasher, MessageDigest},
    pkey::PKey,
    sign::Verifier,
};
use picky_asn1_x509::SubjectPublicKeyInfo;
use std::{
    convert::{Into, TryFrom, TryInto},
    path::Path,
    str::FromStr,
};

use tss_esapi::{
    Context as TssContext,
    abstraction::{
        AsymmetricAlgorithmSelection, DefaultKey, ak, ek, pcr::read_all,
    },
    attributes::ObjectAttributesBuilder,
    constants::session_type::SessionType,
    handles::{
        AuthHandle, KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle,
    },
    interface_types::{
        algorithm::{
            AsymmetricAlgorithm, HashingAlgorithm, PublicAlgorithm,
            SignatureSchemeAlgorithm,
        },
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, Provision},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Attest, AttestInfo, CreatePrimaryKeyResult, Data, Digest, HashScheme,
        KeyedHashScheme, PcrSelectionList, PcrSelectionListBuilder, PcrSlot,
        Public, PublicBuilder, PublicKeyRsa, PublicKeyedHashParameters,
        PublicRsaParameters, RsaExponent, RsaScheme, SensitiveData, Signature,
        SignatureScheme, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
    tss2_esys::TPML_DIGEST,
    utils::get_tpm_vendor,
};

/// TPM context wrapper with methods for:
/// 1. EK, AK creation/loading and persistent store by handles, TODO: AK verification
/// 2. Quote generation using AK on persistent handle;
/// 3. Quote verification on the remote server without TPM hardware;
/// 4. Policy (TODO: and compound policy) creation;
/// 5. Object sealing and unsealing under single (TODO: and compound policy).
pub struct Tpm(TssContext);

/// TPM Endorsement Key
pub struct EK {
    handle: KeyHandle,
    //TODO: AK verification
    pubkey: Public,
    cert: Option<Vec<u8>>,
}

/// TPM Attestation Key under Endorsement Hierarchy
pub struct AK {
    handle: ObjectHandle,
    pubkey: Public,
}

/// TPM Quote
pub struct Quote {
    pub att: Attest,
    pub sig: Signature,
}

impl Tpm {
    /// Creates a connection context
    pub fn new() -> Result<Self> {
        let tcti_path = if Path::new("/dev/tpmrm0").exists() {
            "device:/dev/tpmrm0"
        } else {
            "device:/dev/tpm0"
        }
        .to_string();

        let tcti = TctiNameConf::from_str(&tcti_path)
            .context(format!("TCTI error for device: {}", tcti_path))?;

        let mut tpmctx = TssContext::new(tcti)?;
        debug!("Connected to TPM");
        let tpm_vendor = get_tpm_vendor(&mut tpmctx)?;

        // Warn about non-hardware TPM
        if tpm_vendor.contains("SW") || tpm_vendor.contains("INTC") {
            warn!("FIRMWARE EMULATED TPM FOUND! (TPM vendor: {})", tpm_vendor);
            warn!(
                "Your system doesn't have physical TPM hardware. Integrity measurement might be compromised."
            );
        } else {
            debug!("TPM vendor is: {}", tpm_vendor);
        }

        Ok(Self(tpmctx))
    }

    /// Fetch or create Endorsement Key
    pub fn ek(&mut self, handle: Option<u32>) -> Result<EK> {
        let ek_handle: KeyHandle = if let Some(v) = handle {
            debug!("Fetching EK ...");
            self.0
                .tr_from_tpm_public(TpmHandle::Persistent(
                    PersistentTpmHandle::new(v)?,
                ))?
                .into()
        } else {
            debug!("Creating EK ...");
            ek::create_ek_object(
                &mut self.0,
                AsymmetricAlgorithm::Rsa,
                DefaultKey,
            )?
        };

        let ek_pubcert = ek::retrieve_ek_pubcert(
            &mut self.0,
            AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        )
        .ok();
        if ek_pubcert.is_none() {
            warn!("No EK certificate found in TPM NVRAM");
        }

        let (ek_pub, _, _) = self.0.read_public(ek_handle)?;

        Ok(EK {
            handle: ek_handle,
            pubkey: ek_pub,
            cert: ek_pubcert,
        })
    }

    /// Create Attestation Key under Endorsement Hierarchy and make it persistent
    pub fn ak_create(&mut self, ek: EK) -> Result<AK> {
        debug!("Creating persistent AK ...");
        let ak_res = ak::create_ak(
            &mut self.0,
            ek.handle,
            HashingAlgorithm::Sha256,
            SignatureSchemeAlgorithm::RsaSsa,
            None,
            DefaultKey,
        )?;
        let transient_ak_handle = self
            .0
            .execute_with_nullauth_session(|ctx| {
                ak::load_ak(
                    ctx,
                    ek.handle,
                    None,
                    ak_res.out_private.clone(),
                    ak_res.out_public.clone(),
                )
            })
            .context("Failed to load transient AK")?;
        debug!("Transient AK loaded with handle: {:?}", transient_ak_handle);

        self.evict(CONF_TPM_AK_PERSISTENT_HANDLE)?;
        let ak_handle = self
            .0
            .execute_with_nullauth_session(|ctx| {
                ctx.evict_control(
                    Provision::Owner,
                    transient_ak_handle.into(),
                    PersistentTpmHandle::new(CONF_TPM_AK_PERSISTENT_HANDLE)?
                        .into(),
                )
            })
            .context(format!(
                "Failed to make AK persistent at handle 0x{:x}",
                CONF_TPM_AK_PERSISTENT_HANDLE
            ))?;
        debug!(
            "AK successfully persisted at handle: 0x{:x}",
            CONF_TPM_AK_PERSISTENT_HANDLE
        );

        Ok(AK {
            handle: ak_handle,
            pubkey: ak_res.out_public,
        })
    }

    /// Load existing persistent Attestation Key
    pub fn ak_load(&mut self) -> Result<(KeyHandle, AK)> {
        debug!("Loading AK ...");
        debug!(
            "Loading AK from persistent handle 0x{:x}...",
            CONF_TPM_AK_PERSISTENT_HANDLE
        );
        let persistent_handle =
            PersistentTpmHandle::new(CONF_TPM_AK_PERSISTENT_HANDLE)?;
        let key_handle = self
            .0
            .tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
            .context(
                "Failed to create AK transient handle from persistent handle",
            )?
            .into();

        let (pubkey, _, _) = self
            .0
            .read_public(key_handle)
            .context("Failed to read public key from AK persistent handle")?;

        Ok((
            key_handle,
            AK {
                handle: CONF_TPM_AK_PERSISTENT_HANDLE.into(),
                pubkey,
            },
        ))
    }

    /// Generate TPM quote with qualifying data over PCR set.
    pub fn quote(
        &mut self,
        nonce: &[u8],
        pcr_set: PcrSelectionList,
        ak_handle: KeyHandle,
    ) -> Result<Quote> {
        debug!("Issuing TPM quote ...");
        let (att, sig) = self.0.execute_with_nullauth_session(move |ctx| {
            let nonce: Data = nonce.try_into()?;
            ctx.quote(
                ak_handle,
                nonce,
                SignatureScheme::RsaSsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                pcr_set,
            )
        })?;

        Ok(Quote { att, sig })
    }

    /// Check quote without TPM present
    pub fn check_quote(
        ak_pem: String,
        marshalled_quote: String,
        expected_nonce: &[u8],
        expected_pcr_digest: &[u8],
    ) -> Result<()> {
        debug!("Checking TPM quote...");
        let quote = Quote::unmarshall(&marshalled_quote)?;
        let pkey = PKey::public_key_from_pem(ak_pem.as_bytes())
            .context("Could not decode PEM AK public key")?;
        let expected_pcr_digest = Digest::try_from(expected_pcr_digest)
            .context("Could not decode PCR digest")?;

        // Perform RSA SSA (PKCS#1 v1.5) verification using OpenSSL
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
        verifier.update(quote.att.marshall()?.as_slice())?;
        let sig_bytes = match &quote.sig {
            Signature::RsaSsa(rsa_sig) => rsa_sig.signature().as_slice(),
            _ => bail!(
                "Quote signature is not RSA SSA, cannot verify. Type: {:?}",
                quote.sig
            ),
        };
        let is_valid = verifier
            .verify(sig_bytes)
            .context("Quote could not be verified")?;

        ensure!(is_valid, "Quote signature verification failed!");
        ensure!(
            Self::pcr_digest_assert(&expected_pcr_digest, &quote.att)?,
            "Quote PCR digest assertion failed!"
        );

        // Verify qualifying data
        let quote_nonce = quote.att.extra_data();
        ensure!(
            quote_nonce.as_slice() == expected_nonce,
            "Quote qualifying data forgery detected"
        );

        Ok(())
    }

    /// Clear stored values under Owner Hierarchy
    pub fn clear(&mut self) -> Result<()> {
        self.0.clear(AuthHandle::Owner)?;
        self.0.clear_sessions();
        Ok(())
    }

    /// Get clock info from the TPM.
    /// Use existing AK if `nonce` is provided.
    /// If `ak_handle` is not given, loads AK.
    pub fn clock_info(
        &mut self,
        ak_handle: &KeyHandle,
    ) -> Result<(Attest, Signature)> {
        let (att, sig) = self.0.execute_with_sessions(
            (
                Some(AuthSession::Password),
                Some(AuthSession::Password),
                None,
            ),
            |ctx| {
                ctx.get_time(
                    ak_handle.clone(),
                    Data::default(),
                    SignatureScheme::RsaSsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                )
                .context("Could not get attested clock info")
            },
        )?;

        Ok((att, sig))
    }

    /// Get restart count (machine reboot count)
    pub fn restart_count(
        &mut self,
        ak_handle: Option<KeyHandle>,
    ) -> Result<u32> {
        let ak_handle = if let Some(ak_handle) = ak_handle {
            ak_handle
        } else {
            self.ak_load()?.0
        };
        let (att, _) = self.clock_info(&ak_handle)?;
        Ok(att.clock_info().reset_count())
    }

    /// Get PCRs digest
    pub fn pcr_digest(&mut self, pcrlist: &PcrSelectionList) -> Result<Digest> {
        let pcr_data = self
            .0
            .execute_without_session(|ctx| read_all(ctx, pcrlist.clone()))
            .map_err(|e| anyhow!("Could not read PCRs blob: {}", e))?;
        let pcr_data = Vec::<TPML_DIGEST>::from(pcr_data.clone());
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        for tpml_digest in pcr_data {
            for i in 0..tpml_digest.count {
                let pcr = tpml_digest.digests[i as usize];
                hasher.update(&pcr.buffer[..pcr.size as usize])?;
            }
        }
        let pcr_digest = hasher.finish()?;

        Ok((*pcr_digest).try_into()?)
    }

    pub fn pcr_selection_from_str(
        pcr_selection: &str,
    ) -> Result<PcrSelectionList> {
        let parts: Vec<&str> = pcr_selection.split(':').collect();
        if parts.len() != 2 {
            bail!("Inconsistent params");
        }

        if parts[0] != "sha256" {
            bail!("Unsupported hashing algorithm");
        }

        let pcr_indices: Vec<u32> = parts[1]
            .split(',')
            .map(|s| s.parse::<u32>())
            .collect::<Result<Vec<u32>, _>>()
            .map_err(|_| anyhow!("Invalid PCR slot numbers sequence"))?;

        let pcr_slots: Vec<PcrSlot> = pcr_indices
            .into_iter()
            .map(|v| {
                Ok(match v {
                    0 => PcrSlot::Slot0,
                    1 => PcrSlot::Slot1,
                    2 => PcrSlot::Slot2,
                    3 => PcrSlot::Slot3,
                    4 => PcrSlot::Slot4,
                    5 => PcrSlot::Slot5,
                    6 => PcrSlot::Slot6,
                    7 => PcrSlot::Slot7,
                    8 => PcrSlot::Slot8,
                    9 => PcrSlot::Slot9,
                    10 => PcrSlot::Slot10,
                    11 => PcrSlot::Slot11,
                    12 => PcrSlot::Slot12,
                    13 => PcrSlot::Slot13,
                    14 => PcrSlot::Slot14,
                    15 => PcrSlot::Slot15,
                    16 => PcrSlot::Slot16,
                    17 => PcrSlot::Slot17,
                    18 => PcrSlot::Slot18,
                    19 => PcrSlot::Slot19,
                    20 => PcrSlot::Slot20,
                    21 => PcrSlot::Slot21,
                    22 => PcrSlot::Slot22,
                    23 => PcrSlot::Slot23,
                    24 => PcrSlot::Slot24,
                    25 => PcrSlot::Slot25,
                    26 => PcrSlot::Slot26,
                    27 => PcrSlot::Slot27,
                    28 => PcrSlot::Slot28,
                    29 => PcrSlot::Slot29,
                    30 => PcrSlot::Slot30,
                    31 => PcrSlot::Slot31,
                    _ => bail!("0-31 PCR slots are only supported"),
                })
            })
            .collect::<Result<Vec<PcrSlot>, _>>()?;

        Ok(PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &pcr_slots)
            .build()?)
    }

    /// Creates a policy digest of the current state of specific PCRs.
    pub fn policy(
        &mut self,
        pcr_selection: PcrSelectionList,
    ) -> Result<Digest> {
        debug!("Creating PCR policy digest ...");
        let policy_session =
            self.start_policy_session(Some(pcr_selection), true)?;

        let policy_digest = self
            .0
            .policy_get_digest(policy_session)
            .context("Failed to get policy digest.")?;

        Ok(policy_digest)
    }

    /// Seal data authenticated with given policy on given persistent handle
    pub fn seal(
        &mut self,
        data: &[u8],
        persistent_handle: u32,
        policy_digest: Digest,
    ) -> Result<()> {
        if data.len() > 128 {
            bail!("Sealed data must not exceed 128 bytes");
        }
        debug!(
            "Sealing data {} bytes on persistent handle 0x{:x} ...",
            data.len(),
            persistent_handle
        );

        let primary_key = self.primary_key()?;

        let data_sensitive = SensitiveData::try_from(data)
            .context("Could not convert data to SensitiveData")?;

        // Parameter composition matters
        // See tpm2-tools source/man pages for reference
        let seal_key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::Null,
            ))
            .with_keyed_hash_unique_identifier(Digest::default())
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .build()
                    .context(
                        "Could not build ObjectAttributes for seal_key_pub",
                    )?,
            )
            // Seal under given policy
            .with_auth_policy(policy_digest)
            .build()
            .context("Could not build seal_key_pub")?;

        self.evict(persistent_handle)?;
        self.0.execute_with_nullauth_session(|ctx| {
            let seal_key = ctx
                .create(
                    primary_key.key_handle,
                    seal_key_pub,
                    None,
                    Some(data_sensitive),
                    None,
                    None,
                )
                .context("Could not seal data")?;

            // Persist sealed data
            let transient_handle = ctx
                .load(
                    primary_key.key_handle,
                    seal_key.out_private.clone(),
                    seal_key.out_public.clone(),
                )
                .context("Could not load sealed data")?;
            ctx.evict_control(
                Provision::Owner,
                transient_handle.into(),
                PersistentTpmHandle::new(persistent_handle)
                    .context("Could not create persistent handle")?
                    .into(),
            )
            .context("Could not persist sealed data")
        })?;

        debug!("Sealed data successfully");

        Ok(())
    }

    /// Unseal previously sealed data authenticated with policy over given PCR set on specified persistent handle.
    /// If the PCRs state is not conformant with the policy, unsealing will fail.
    pub fn unseal(
        &mut self,
        persistent_handle: u32,
        pcr_selection: PcrSelectionList,
    ) -> Result<SensitiveData> {
        debug!("Unsealing data on handle 0x{:x} ...", persistent_handle);
        let policy_session =
            self.start_policy_session(Some(pcr_selection), false)?;
        let handle = self
            .0
            .tr_from_tpm_public(TpmHandle::Persistent(
                PersistentTpmHandle::new(persistent_handle)
                    .context("Could not parse persistent handle")?,
            ))
            .context(
                "Could not fetch ObjectHandle for given persistent handle",
            )?;

        let data = self
            .0
            .execute_with_session(Some(policy_session.into()), |ctx| {
                ctx.unseal(handle).context("Could not unseal data")
            })?;

        Ok(data)
    }

    /// Assert PCRs digest against attestation data in TPM quote
    fn pcr_digest_assert(
        pcr_digest: &Digest,
        attestation: &Attest,
    ) -> Result<bool> {
        let quote_info = match attestation.attested() {
            AttestInfo::Quote { info } => info,
            _ => {
                bail!(
                    "Unexpected attestation type in quote: {:?}",
                    attestation.attestation_type()
                );
            }
        };
        let attested_pcr_digest = quote_info.pcr_digest();

        Ok(attested_pcr_digest == pcr_digest)
    }

    /// Start policy session with optional condition over PCR set
    fn start_policy_session(
        &mut self,
        pcr_selection: Option<PcrSelectionList>,
        trial: bool,
    ) -> Result<PolicySession> {
        let session = self
            .0
            .start_auth_session(
                None,
                None,
                None,
                if trial {
                    SessionType::Trial
                } else {
                    SessionType::Policy
                },
                SymmetricDefinitionObject::AES_128_CFB.into(),
                HashingAlgorithm::Sha256,
            )
            .context("Failed to start policy session")?
            .ok_or(anyhow!("Received invalid handle"))?;
        let policy_session = PolicySession::try_from(session)
            .context("Failed to convert session handle to PolicySession")?;

        if let Some(pcr_selection) = pcr_selection {
            debug!("PCR Selection for policy: {:?}", pcr_selection);
            self.0
                .policy_pcr(policy_session, Digest::default(), pcr_selection)
                .context(
                    "Failed to make condition of policy digest for selected PCRs",
                )?;
        }

        Ok(policy_session)
    }

    /// Evict previously loaded persistent value
    fn evict(&mut self, persistent_handle: u32) -> Result<()> {
        let handle = PersistentTpmHandle::new(persistent_handle)
            .context("Could not parse persistent handle")?;

        if let Ok(object_handle) =
            self.0.tr_from_tpm_public(TpmHandle::Persistent(handle))
        {
            if let Ok(ObjectHandle::None) =
                self.0.execute_with_nullauth_session(|ctx| {
                    ctx.evict_control(
                        Provision::Owner,
                        object_handle,
                        handle.into(),
                    )
                })
            {
                debug!(
                    "Removed previous value at handle 0x{:x}",
                    persistent_handle
                );
            }
        }

        Ok(())
    }

    /// Generate primary key
    fn primary_key(&mut self) -> Result<CreatePrimaryKeyResult> {
        // Parameter composition matters
        // See tpm2-tools source/man pages for reference
        let primary_key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_rsa_unique_identifier(PublicKeyRsa::new_empty_with_size(
                RsaKeyBits::Rsa2048,
            ))
            .with_rsa_parameters(PublicRsaParameters::new(
                SymmetricDefinitionObject::AES_128_CFB,
                RsaScheme::Null,
                RsaKeyBits::Rsa2048,
                RsaExponent::default(),
            ))
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_restricted(true)
                    .with_decrypt(true)
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .build()
                    .context(
                        "Could not build ObjectAttributes for primary_key_pub",
                    )?,
            )
            .build()
            .context("Could not build primary_key_pub")?;

        let primary_key = self.0.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                primary_key_pub,
                None,
                None,
                None,
                None,
            )
            .context("Could not create primary_key")
        })?;

        Ok(primary_key)
    }
}

impl EK {
    pub fn handle(&self) -> KeyHandle {
        self.handle
    }

    pub fn cert_pem(&self) -> Option<String> {
        if let Some(ref _cert) = self.cert {
            //TODO
            None
        } else {
            None
        }
    }

    pub fn pub_pem(&self) -> Result<String> {
        Ok(tss_pubkey_to_pem(self.pubkey.clone())?)
    }
}

impl AK {
    pub fn handle(&self) -> ObjectHandle {
        self.handle
    }

    pub fn to_pem(&self) -> Result<String> {
        Ok(tss_pubkey_to_pem(self.pubkey.clone())?)
    }
}

impl Quote {
    pub fn marshall(&self) -> Result<String> {
        let att_str = general_purpose::STANDARD.encode(&self.att.marshall()?);
        let sig_str = general_purpose::STANDARD.encode(&self.sig.marshall()?);

        Ok(format!("{}:{}", att_str, sig_str))
    }

    pub fn unmarshall(marshalled: &str) -> Result<Self> {
        let att_sig: Vec<&str> = marshalled.split(":").collect();
        if att_sig.len() != 2 {
            bail!("Marshalled quote format is incorrect");
        }
        Ok(Self {
            att: Attest::unmarshall(
                &general_purpose::STANDARD
                    .decode(att_sig.get(0).unwrap())
                    .context("Could not decode quote data")?,
            )
            .context("Could not unmarshall quote data")?,
            sig: Signature::unmarshall(
                &general_purpose::STANDARD
                    .decode(att_sig.get(1).unwrap())
                    .context("Could not decode quote signature")?,
            )
            .context("Could not unmarshall quote signature")?,
        })
    }
}

// Encode a TSS Public key in PEM format
fn tss_pubkey_to_pem(pubkey: Public) -> Result<String> {
    // Converting Public TSS key to PEM
    let key: SubjectPublicKeyInfo = pubkey.try_into()?;
    let key_der = picky_asn1_der::to_vec(&key)?;
    let openssl_key = PKey::public_key_from_der(&key_der)?;
    let pem = openssl_key.public_key_to_pem()?;
    let pem_str = String::from_utf8_lossy(&pem);
    Ok(pem_str.into())
}

/// This tests requires TPM to be present
#[cfg(test)]
mod tests {

    use super::*;
    use std::{thread, time::Duration};
    use tss_esapi::{
        handles::PcrHandle,
        structures::{PcrSlot, digest_values::DigestValues},
    };

    const CONF_PERSISTENT_HANDLE_1: u32 = 0x81010394;
    const CONF_PERSISTENT_HANDLE_2: u32 = 0x81010395;

    #[test]
    fn quote_generate_verify_and_clock_info() {
        // Using multiple tests in one function as they depend on AK persistent handle
        // so single threaded tests are required
        let mut ctx = Tpm::new().expect("Could not connect to TPM chip");
        let ek = ctx.ek(None).expect("Could not create EK");
        let ek_handle = ek.handle();
        let ak = ctx.ak_create(ek).expect("Could not create AK");
        let (ak_handle, _) = ctx.ak_load().expect("Could not load AK");
        let ak_pem = ak.to_pem().expect("Could not convert AK to PEM");
        let nonce = "this is qualifying data".as_bytes();

        let clock_info_ak =
            ctx.clock_info(&ak_handle).expect("clock_info1 failure");
        let clock_info_ak = clock_info_ak.0.clock_info().clone();

        let pcr_set_builder = PcrSelectionList::builder();
        let pcr_set = pcr_set_builder
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot1],
            )
            .build()
            .expect("Could not build PCR set");
        let pcr_digest =
            ctx.pcr_digest(&pcr_set).expect("Could not get PCRs digest");

        thread::sleep(Duration::from_secs(1));

        let quote = ctx
            .quote(nonce, pcr_set, ak_handle)
            .expect("Could not issue quote");
        let marshalled_quote =
            quote.marshall().expect("Could not marshall quote");

        Tpm::check_quote(ak_pem, marshalled_quote.clone(), nonce, &pcr_digest)
            .expect("Could not verify quote");

        let mut ak_object_handle: ObjectHandle = ak_handle.into();
        ctx.0
            .tr_close(&mut ak_object_handle)
            .expect("Error in AK resources free");
        ctx.0
            .flush_context(ek_handle.into())
            .expect("Could not flush EK context");

        let clock_info = quote.att.clock_info().clone();
        let clock_diff = clock_info.clock() - clock_info_ak.clock();

        assert!(
            clock_diff > 1000 && clock_diff < 3000,
            "ClockInfo tests failed as timestamp difference is incorrect"
        );
    }

    #[test]
    fn seal_unseal() {
        let pcr_set_builder = PcrSelectionList::builder();
        let pcr_set = pcr_set_builder
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot1],
            )
            .build()
            .expect("Could not build PCR set");

        let mut ctx = Tpm::new().expect("Could not connect to TPM chip");
        let test_data = b"my secret data".as_slice();
        let policy = ctx
            .policy(pcr_set.clone())
            .expect("Could not create policy digest");
        ctx.seal(&test_data, CONF_PERSISTENT_HANDLE_1, policy)
            .expect("Could not seal data in test");
        let unsealed_data = ctx
            .unseal(CONF_PERSISTENT_HANDLE_1, pcr_set)
            .expect("Could not unseal data");
        assert_eq!(
            test_data,
            unsealed_data.as_slice(),
            "Unsealed data corrupted"
        );
    }

    #[test]
    fn seal_unseal_failure() {
        let pcr_slot_to_test = PcrSlot::Slot16;
        let pcr_handle = PcrHandle::Pcr16;
        let pcr_set = PcrSelectionList::builder()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot15, pcr_slot_to_test],
            )
            .build()
            .expect("Could not build PCR set for failure test");

        let mut ctx = Tpm::new().expect("Could not connect to TPM chip");

        let policy = ctx
            .policy(pcr_set.clone())
            .expect("Could not create initial policy digest");
        let test_data = b"data sealed before pcr change".as_slice();
        ctx.seal(test_data, CONF_PERSISTENT_HANDLE_2, policy)
            .expect("Could not seal data before PCR change");

        // Extend PCR 16 to change its value
        let mut digests = DigestValues::new();
        digests.set(
            HashingAlgorithm::Sha256,
            Digest::try_from([0xau8; 32].as_ref()).unwrap(),
        );
        ctx.0
            .execute_with_nullauth_session(|ctx| {
                ctx.pcr_extend(pcr_handle, digests)
            })
            .expect("Failed to extend PCR 16");

        // Attempt to unseal - this should fail because PCR 16 has been changed
        let unseal_result =
            ctx.unseal(CONF_PERSISTENT_HANDLE_2, pcr_set.clone());

        // Assert that unsealing failed
        assert!(
            unseal_result.is_err(),
            "Unsealing should have failed after PCR extension, but it succeeded."
        );
    }
}
