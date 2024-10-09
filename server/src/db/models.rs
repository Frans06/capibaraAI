use crate::db::schema::user;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Clone, Debug)]
#[diesel(table_name = crate::db::schema::user)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub access_token: String,
}

#[derive(Insertable)]
#[diesel(table_name = user)]
pub struct NewUser<'a> {
    pub id: &'a str,
    pub email: &'a str,
    pub access_token: &'a str,
    pub name: &'a str,
}
