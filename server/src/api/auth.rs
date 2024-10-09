use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use axum_login::tower_sessions::Session;
use leptos::LeptosOptions;
use serde::{Deserialize, Serialize};

pub const NEXT_URL_KEY: &str = "auth.next-url";

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

pub fn router() -> Router<LeptosOptions> {
    Router::new()
        .route("/auth/login", get(self::get::login))
        .route("/auth/logout", get(self::get::logout))
}

#[derive(Serialize)]
struct UrlResponse {
    url: String,
}

mod get {

    use axum::Json;

    use crate::{api::oauth::CSRF_STATE_KEY, auth::AuthSession};

    use super::*;

    pub async fn login(
        auth_session: AuthSession,
        session: Session,
        Form(NextUrl { next }): Form<NextUrl>,
    ) -> Json<UrlResponse> {
        let (auth_url, csrf_state) = auth_session.backend.authorize_url();

        session
            .insert(CSRF_STATE_KEY, csrf_state.secret())
            .await
            .expect("Serialization should not fail.");

        session
            .insert(NEXT_URL_KEY, next)
            .await
            .expect("Serialization should not fail.");
        let response = UrlResponse {
            url: auth_url.as_str().to_owned(),
        };
        Json(response)
    }

    pub async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.logout().await {
            Ok(_) => Redirect::to("/login").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
