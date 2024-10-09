use async_trait::async_trait;
use axum::http::header::{AUTHORIZATION, USER_AGENT};
use axum_login::{AuthnBackend, UserId};
use db::models::{NewUser, User};
use diesel::{
    r2d2::{ConnectionManager, Pool},
    ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl, SelectableHelper,
};
use oauth2::{
    basic::{BasicClient, BasicRequestTokenError},
    reqwest::{async_http_client, AsyncHttpClientError},
    url::Url,
    AuthorizationCode, CsrfToken, Scope, TokenResponse,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    email: String,
    name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    Database(diesel::result::Error),

    #[error(transparent)]
    Reqwest(reqwest::Error),

    #[error(transparent)]
    OAuth2(BasicRequestTokenError<AsyncHttpClientError>),
}

#[derive(Clone)]
pub struct Backend {
    db: Pool<ConnectionManager<PgConnection>>,
    client: BasicClient,
}

impl Backend {
    pub fn new(db: Pool<ConnectionManager<PgConnection>>, client: BasicClient) -> Self {
        Self { db, client }
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken) {
        self.client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            .url()
    }
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        use db::schema::user;
        // Ensure the CSRF state has not been tampered with.

        if creds.old_state.secret() != creds.new_state.secret() {
            return Ok(None);
        };

        // Process authorization code, expecting a token response back.
        let token_res = self
            .client
            .exchange_code(AuthorizationCode::new(creds.code))
            .request_async(async_http_client)
            .await
            .map_err(Self::Error::OAuth2)?;

        // Use access token to request user info.

        let mut url = Url::parse("https://www.googleapis.com/oauth2/v1/userinfo").unwrap();
        url.query_pairs_mut().append_pair("alt", "json");

        let user_info = reqwest::Client::new()
            .get(url)
            .header(USER_AGENT.as_str(), "axum-login") // See: https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28#user-agent-required
            .header(
                AUTHORIZATION.as_str(),
                format!("Bearer {}", token_res.access_token().secret()),
            )
            .send()
            .await
            .map_err(Self::Error::Reqwest)?
            .json::<UserInfo>()
            .await
            .map_err(Self::Error::Reqwest)?;

        let new_user = NewUser {
            id: &cuid::cuid2(),
            email: &user_info.email,
            access_token: token_res.access_token().secret(),
            name: &user_info.name,
        };
        let pool = self.db.clone();
        let created_user = diesel::insert_into(user::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(&mut pool.get().unwrap())
            .map_err(Self::Error::Database)?;

        Ok(Some(created_user))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        use db::schema::user::dsl::*;
        let pool = self.db.clone();
        let result = user
            .filter(id.eq(user_id))
            .select(User::as_select())
            .load(&mut pool.get().unwrap())
            .map_err(Self::Error::Database)
            .unwrap()
            .into_iter()
            .nth(0)
            .unwrap();
        Ok(Some(result))
    }
}

// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type AuthSession = axum_login::AuthSession<Backend>;
