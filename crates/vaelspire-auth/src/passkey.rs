//! Passkey registration and login.
//!
//! The relying party id and origin are arguments. They are not stored, and they are not
//! constants of this crate. Between begin and finish the ceremony state is JSON in the
//! store's ceremony column; the challenge column keeps the raw challenge bytes. Finish
//! deletes that row.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use time::Duration;
use url::Url;
use vaelspire_core::{AuthError, AuthStore, Id, PasskeyRecord, Session, Timestamp};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, WebauthnBuilder,
};

use crate::{Auth, IssuedSession, Meta};

const KIND_REGISTER: &str = "passkey_register";
const KIND_LOGIN: &str = "passkey_login";
const CEREMONY_TTL: Duration = Duration::minutes(5);

impl<S: AuthStore> Auth<'_, S> {
    /// Start passkey registration for an existing account.
    ///
    /// `rp_id` and `origin` are the caller's relying party. The returned JSON is the
    /// challenge to hand to the client. The ceremony state stays in the store.
    ///
    /// # Errors
    /// Returns `Invalid` for a relying party the `WebAuthn` builder rejects, `Unauthorized`
    /// when the account cannot be read, or `Store` on I/O or serialization failure.
    #[cfg(feature = "passkey")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn begin_passkey_registration(
        &self,
        user: Id,
        rp_id: &str,
        origin: &str,
        now: Timestamp,
    ) -> Result<serde_json::Value, AuthError> {
        self.begin_passkey_registration_with(None, user, rp_id, origin, now)
            .await
    }

    pub(crate) async fn begin_passkey_registration_with(
        &self,
        _meta: Option<Meta<'_>>,
        user: Id,
        rp_id: &str,
        origin: &str,
        now: Timestamp,
    ) -> Result<serde_json::Value, AuthError> {
        let existing = self.store.list_passkeys(user).await?;
        let (challenge, ceremony, response) = {
            let exclude = exclude_ids(&existing);
            let webauthn = webauthn(rp_id, origin)?;
            let (response, state) = webauthn
                .start_passkey_registration(user, &user.to_string(), &user.to_string(), exclude)
                .map_err(|_| AuthError::Unauthorized)?;
            let challenge = response.public_key.challenge.as_ref().to_vec();
            let ceremony = serde_json::to_string(&state).map_err(|_| AuthError::Store)?;
            let response = serde_json::to_value(response).map_err(|_| AuthError::Store)?;
            (challenge, ceremony, response)
        };
        self.store
            .save_passkey_ceremony(
                user,
                KIND_REGISTER,
                &challenge,
                &ceremony,
                now + CEREMONY_TTL,
            )
            .await?;
        Ok(response)
    }

    /// Finish passkey registration and store the credential as JSON.
    ///
    /// # Errors
    /// Returns `Invalid` for a malformed client response, `Unauthorized` for a ceremony
    /// that does not belong to `user` or a response the authenticator check rejects, or
    /// `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn finish_passkey_registration(
        &self,
        user: Id,
        rp_id: &str,
        origin: &str,
        credential: serde_json::Value,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.finish_passkey_registration_with(None, user, rp_id, origin, credential, now)
            .await
    }

    pub(crate) async fn finish_passkey_registration_with(
        &self,
        meta: Option<Meta<'_>>,
        user: Id,
        rp_id: &str,
        origin: &str,
        credential: serde_json::Value,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let challenge = client_challenge(&credential)?;
        let (owner, ceremony) = self
            .store
            .load_passkey_ceremony(KIND_REGISTER, &challenge, now)
            .await?;
        if owner != user {
            return Err(AuthError::Unauthorized);
        }
        let record = {
            let state: PasskeyRegistration =
                serde_json::from_str(&ceremony).map_err(|_| AuthError::Store)?;
            let reg: RegisterPublicKeyCredential =
                serde_json::from_value(credential).map_err(|_| AuthError::Invalid)?;
            let webauthn = webauthn(rp_id, origin)?;
            let passkey = webauthn
                .finish_passkey_registration(&reg, &state)
                .map_err(|_| AuthError::Unauthorized)?;
            record_of(&passkey, 0)?
        };
        let audit = self.audit_event(
            meta,
            None,
            Some(user),
            crate::ACTION_PASSKEY_REGISTERED,
            "ok",
        );
        self.store
            .complete_passkey_registration(user, KIND_REGISTER, &challenge, &record, audit, now)
            .await
    }

    /// Start passkey login for an account identified by email.
    ///
    /// # Errors
    /// Returns `Unauthorized` for an unknown account or an account with no passkey,
    /// `Invalid` for a bad email or relying party, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn begin_passkey_login(
        &self,
        tenant: Id,
        email: &str,
        rp_id: &str,
        origin: &str,
        now: Timestamp,
    ) -> Result<serde_json::Value, AuthError> {
        self.begin_passkey_login_with(None, tenant, email, rp_id, origin, now)
            .await
    }

    pub(crate) async fn begin_passkey_login_with(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Id,
        email: &str,
        rp_id: &str,
        origin: &str,
        now: Timestamp,
    ) -> Result<serde_json::Value, AuthError> {
        let email = crate::normalized_email(email)?;
        let user = match self
            .store
            .find_user(tenant, &email)
            .await
            .map_err(crate::hide_missing)
        {
            Ok(user) => user,
            Err(AuthError::Unauthorized) => {
                self.record(
                    meta,
                    Some(tenant),
                    None,
                    crate::ACTION_SESSION_DENIED,
                    "denied",
                    now,
                )
                .await?;
                return Err(AuthError::Unauthorized);
            }
            Err(error) => return Err(error),
        };
        let records = self.store.list_passkeys(user.id).await?;
        if records.is_empty() {
            self.record(
                meta,
                Some(tenant),
                Some(user.id),
                crate::ACTION_SESSION_DENIED,
                "denied",
                now,
            )
            .await?;
            return Err(AuthError::Unauthorized);
        }
        let (challenge, ceremony, response) = {
            let passkeys = deserialize_passkeys(&records)?;
            let webauthn = webauthn(rp_id, origin)?;
            let (response, state) = webauthn
                .start_passkey_authentication(&passkeys)
                .map_err(|_| AuthError::Unauthorized)?;
            let challenge = response.public_key.challenge.as_ref().to_vec();
            let ceremony = serde_json::to_string(&state).map_err(|_| AuthError::Store)?;
            let response = serde_json::to_value(response).map_err(|_| AuthError::Store)?;
            (challenge, ceremony, response)
        };
        self.store
            .save_passkey_ceremony(
                user.id,
                KIND_LOGIN,
                &challenge,
                &ceremony,
                now + CEREMONY_TTL,
            )
            .await?;
        Ok(response)
    }

    /// Finish passkey login and issue a session.
    ///
    /// # Errors
    /// Returns `Invalid` for a malformed client response, `Unauthorized` for a missing
    /// ceremony or a rejected assertion, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn finish_passkey_login(
        &self,
        rp_id: &str,
        origin: &str,
        credential: serde_json::Value,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        self.finish_passkey_login_with(None, rp_id, origin, credential, now)
            .await
    }

    pub(crate) async fn finish_passkey_login_with(
        &self,
        meta: Option<Meta<'_>>,
        rp_id: &str,
        origin: &str,
        credential: serde_json::Value,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        let challenge = client_challenge(&credential)?;
        let (user, ceremony) = self
            .store
            .load_passkey_ceremony(KIND_LOGIN, &challenge, now)
            .await?;
        let verified = {
            let state: PasskeyAuthentication =
                serde_json::from_str(&ceremony).map_err(|_| AuthError::Store)?;
            let assertion: PublicKeyCredential =
                serde_json::from_value(credential).map_err(|_| AuthError::Invalid)?;
            let webauthn = webauthn(rp_id, origin)?;
            webauthn.finish_passkey_authentication(&assertion, &state)
        };
        let Ok(result) = verified else {
            let tenant = self.store.user_tenant(user).await.ok();
            self.record(
                meta,
                tenant,
                Some(user),
                crate::ACTION_SESSION_DENIED,
                "denied",
                now,
            )
            .await?;
            return Err(AuthError::Unauthorized);
        };
        let records = self.store.list_passkeys(user).await?;
        let record = {
            let mut stored = records
                .into_iter()
                .find_map(|record| {
                    let passkey: Passkey = serde_json::from_slice(&record.public_key).ok()?;
                    (passkey.cred_id().as_ref() == result.cred_id().as_ref()).then_some(passkey)
                })
                .ok_or(AuthError::Unauthorized)?;
            if stored.update_credential(&result).is_none() {
                return Err(AuthError::Unauthorized);
            }
            record_of(&stored, i64::from(result.counter()))?
        };
        let tenant = self
            .store
            .user_tenant(user)
            .await
            .map_err(crate::hide_missing)?;
        let token = crate::random_secret()?;
        let (keyed, digest_hex) = self.session_digest(token.expose());
        let session = Session {
            id: Id::now_v7(),
            user_id: user,
            tenant_id: tenant,
            token_digest: crate::versioned(keyed),
            expires_at: now + self.policy.session_ttl,
        };
        let audit = self.audit_event(
            meta,
            Some(tenant),
            Some(user),
            crate::ACTION_SESSION_ISSUED,
            "ok",
        );
        self.store
            .complete_passkey_login(KIND_LOGIN, &challenge, &session, &record, audit, now)
            .await?;
        Ok(IssuedSession { token, digest_hex })
    }
}

impl<S: AuthStore> crate::Call<'_, S> {
    /// [`Auth::begin_passkey_registration`] with this call's request metadata.
    ///
    /// # Errors
    /// As [`Auth::begin_passkey_registration`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn begin_passkey_registration(
        &self,
        user: Id,
        rp_id: &str,
        origin: &str,
        now: Timestamp,
    ) -> Result<serde_json::Value, AuthError> {
        self.auth
            .begin_passkey_registration_with(Some(self.meta()), user, rp_id, origin, now)
            .await
    }

    /// [`Auth::finish_passkey_registration`] with this call's request metadata.
    ///
    /// # Errors
    /// As [`Auth::finish_passkey_registration`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn finish_passkey_registration(
        &self,
        user: Id,
        rp_id: &str,
        origin: &str,
        credential: serde_json::Value,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.auth
            .finish_passkey_registration_with(
                Some(self.meta()),
                user,
                rp_id,
                origin,
                credential,
                now,
            )
            .await
    }

    /// [`Auth::begin_passkey_login`] with this call's request metadata.
    ///
    /// # Errors
    /// As [`Auth::begin_passkey_login`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn begin_passkey_login(
        &self,
        tenant: Id,
        email: &str,
        rp_id: &str,
        origin: &str,
        now: Timestamp,
    ) -> Result<serde_json::Value, AuthError> {
        self.auth
            .begin_passkey_login_with(Some(self.meta()), tenant, email, rp_id, origin, now)
            .await
    }

    /// [`Auth::finish_passkey_login`] with this call's request metadata.
    ///
    /// # Errors
    /// As [`Auth::finish_passkey_login`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn finish_passkey_login(
        &self,
        rp_id: &str,
        origin: &str,
        credential: serde_json::Value,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        self.auth
            .finish_passkey_login_with(Some(self.meta()), rp_id, origin, credential, now)
            .await
    }
}

fn webauthn(rp_id: &str, origin: &str) -> Result<webauthn_rs::Webauthn, AuthError> {
    let origin = Url::parse(origin).map_err(|_| AuthError::Invalid)?;
    WebauthnBuilder::new(rp_id, &origin)
        .map_err(|_| AuthError::Invalid)?
        .build()
        .map_err(|_| AuthError::Invalid)
}

fn exclude_ids(records: &[PasskeyRecord]) -> Option<Vec<webauthn_rs::prelude::CredentialID>> {
    if records.is_empty() {
        return None;
    }
    Some(
        records
            .iter()
            .map(|record| record.credential_id.clone().into())
            .collect(),
    )
}

fn deserialize_passkeys(records: &[PasskeyRecord]) -> Result<Vec<Passkey>, AuthError> {
    records
        .iter()
        .map(|record| serde_json::from_slice(&record.public_key).map_err(|_| AuthError::Store))
        .collect()
}

fn record_of(passkey: &Passkey, sign_count: i64) -> Result<PasskeyRecord, AuthError> {
    Ok(PasskeyRecord {
        credential_id: passkey.cred_id().as_ref().to_vec(),
        public_key: serde_json::to_vec(passkey).map_err(|_| AuthError::Store)?,
        sign_count,
    })
}

fn client_challenge(credential: &serde_json::Value) -> Result<Vec<u8>, AuthError> {
    let encoded = credential
        .pointer("/response/clientDataJSON")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthError::Invalid)?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
        .map_err(|_| AuthError::Invalid)?;
    let client: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| AuthError::Invalid)?;
    let challenge = client
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthError::Invalid)?;
    URL_SAFE_NO_PAD
        .decode(challenge)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(challenge))
        .map_err(|_| AuthError::Invalid)
}
