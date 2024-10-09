use axum_login::AuthUser;
use diesel::prelude::*;

use crate::schema;

#[derive(Queryable, Selectable, Clone, Debug)]
#[diesel(table_name = schema::user)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub access_token: String,
}

#[derive(Insertable)]
#[diesel(table_name = schema::user)]
pub struct NewUser<'a> {
    pub id: &'a str,
    pub email: &'a str,
    pub access_token: &'a str,
    pub name: &'a str,
}

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.id.to_owned()
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.access_token.as_bytes()
    }
}
