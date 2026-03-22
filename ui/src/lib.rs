use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gloo_net::http::Request;
use gloo_storage::{LocalStorage, Storage};
use leptos::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

// ────────────────────────────────────────────────────────────
// Constants – adjust to match docker-compose ports
// ────────────────────────────────────────────────────────────
const GATEWAY_BASE: &str = "http://localhost:8080";
const CLIENT_ID: &str = "web-client";
const REDIRECT_URI: &str = "http://localhost:3000/callback";

// ────────────────────────────────────────────────────────────
// Storage keys
// ────────────────────────────────────────────────────────────
const KEY_ACCESS_TOKEN: &str = "access_token";
const KEY_CODE_VERIFIER: &str = "pkce_verifier";

// ────────────────────────────────────────────────────────────
// Data models
// ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
struct User {
    #[serde(rename = "_id")]
    id: String,
    username: String,
    email: String,
    roles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    id_token: String,
    refresh_token: String,
    scope: String,
}

// ────────────────────────────────────────────────────────────
// PKCE helpers
// ────────────────────────────────────────────────────────────

fn generate_code_verifier() -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

fn code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

// ────────────────────────────────────────────────────────────
// App component
// ────────────────────────────────────────────────────────────

#[component]
pub fn App() -> impl IntoView {
    let access_token: RwSignal<Option<String>> =
        create_rw_signal(LocalStorage::get(KEY_ACCESS_TOKEN).ok());

    // Check if this is an OAuth callback (URL contains ?code=...)
    let window = web_sys::window().expect("window");
    let search = window.location().search().unwrap_or_default();
    if search.contains("code=") {
        return view! { <OidcCallback access_token=access_token /> }.into_view();
    }

    view! {
        <div class="container">
            <h1>"DataWorker"</h1>
            {move || if access_token.get().is_some() {
                view! { <Dashboard access_token=access_token /> }.into_view()
            } else {
                view! { <LoginPage /> }.into_view()
            }}
        </div>
    }
}

// ────────────────────────────────────────────────────────────
// Login page
// ────────────────────────────────────────────────────────────

#[component]
fn LoginPage() -> impl IntoView {
    let start_login = move |_| {
        let verifier = generate_code_verifier();
        let challenge = code_challenge(&verifier);
        LocalStorage::set(KEY_CODE_VERIFIER, &verifier).ok();

        let state = uuid::Uuid::new_v4().to_string();
        let auth_url = format!(
            "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid+profile+email&state={}&code_challenge={}&code_challenge_method=S256",
            GATEWAY_BASE, CLIENT_ID, REDIRECT_URI, state, challenge
        );

        web_sys::window()
            .unwrap()
            .location()
            .set_href(&auth_url)
            .ok();
    };

    view! {
        <div class="card" style="max-width:400px;margin:4rem auto;">
            <h2>"Sign in"</h2>
            <p style="margin:1rem 0;color:#555;">"Please sign in to continue."</p>
            <button class="btn btn-primary" on:click=start_login>
                "Sign in with OIDC"
            </button>
        </div>
    }
}

// ────────────────────────────────────────────────────────────
// OIDC callback handler
// ────────────────────────────────────────────────────────────

#[component]
fn OidcCallback(access_token: RwSignal<Option<String>>) -> impl IntoView {
    let error_msg: RwSignal<Option<String>> = create_rw_signal(None);

    create_effect(move |_| {
        let window = web_sys::window().expect("window");
        let search = window.location().search().unwrap_or_default();

        // Parse query params
        let params: std::collections::HashMap<_, _> = search
            .trim_start_matches('?')
            .split('&')
            .filter_map(|p| {
                let mut parts = p.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect();

        let code = match params.get("code") {
            Some(c) => c.clone(),
            None => {
                error_msg.set(Some("No code in callback".to_string()));
                return;
            }
        };

        let verifier: String = match LocalStorage::get(KEY_CODE_VERIFIER) {
            Ok(v) => v,
            Err(_) => {
                error_msg.set(Some("Missing PKCE verifier".to_string()));
                return;
            }
        };
        LocalStorage::delete(KEY_CODE_VERIFIER);

        spawn_local(async move {
            let body = format!(
                "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
                code, REDIRECT_URI, CLIENT_ID, verifier
            );
            match Request::post(&format!("{}/token", GATEWAY_BASE))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
                .unwrap()
                .send()
                .await
            {
                Ok(resp) if resp.ok() => {
                    if let Ok(token_resp) = resp.json::<TokenResponse>().await {
                        LocalStorage::set(KEY_ACCESS_TOKEN, &token_resp.access_token).ok();
                        access_token.set(Some(token_resp.access_token));
                        web_sys::window()
                            .unwrap()
                            .location()
                            .set_href("/")
                            .ok();
                    }
                }
                Ok(resp) => {
                    error_msg.set(Some(format!("Token exchange failed: {}", resp.status())));
                }
                Err(e) => {
                    error_msg.set(Some(format!("Network error: {:?}", e)));
                }
            }
        });
    });

    view! {
        <div class="card" style="max-width:400px;margin:4rem auto;">
            <h2>"Signing in..."</h2>
            {move || error_msg.get().map(|e| view! { <p class="error">{e}</p> })}
        </div>
    }
}

// ────────────────────────────────────────────────────────────
// Dashboard
// ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Users,
    CreateUser,
}

#[component]
fn Dashboard(access_token: RwSignal<Option<String>>) -> impl IntoView {
    let page: RwSignal<Page> = create_rw_signal(Page::Users);

    let logout = move |_| {
        LocalStorage::delete(KEY_ACCESS_TOKEN);
        access_token.set(None);
    };

    view! {
        <div>
            <div class="nav">
                <button
                    class=move || if page.get() == Page::Users { "nav-link active" } else { "nav-link" }
                    on:click=move |_| page.set(Page::Users)
                >"Users"</button>
                <button
                    class=move || if page.get() == Page::CreateUser { "nav-link active" } else { "nav-link" }
                    on:click=move |_| page.set(Page::CreateUser)
                >"Create User"</button>
                <button class="nav-link" style="margin-left:auto;" on:click=logout>"Sign out"</button>
            </div>
            {move || match page.get() {
                Page::Users => view! { <UserList access_token=access_token /> }.into_view(),
                Page::CreateUser => view! { <CreateUserForm
                    access_token=access_token
                    on_created=move || page.set(Page::Users)
                /> }.into_view(),
            }}
        </div>
    }
}

// ────────────────────────────────────────────────────────────
// User list
// ────────────────────────────────────────────────────────────

#[component]
fn UserList(access_token: RwSignal<Option<String>>) -> impl IntoView {
    let users: RwSignal<Vec<User>> = create_rw_signal(vec![]);
    let error_msg: RwSignal<Option<String>> = create_rw_signal(None);
    let loading: RwSignal<bool> = create_rw_signal(false);

    let fetch_users = {
        let access_token = access_token;
        move || {
            let token = match access_token.get() {
                Some(t) => t,
                None => return,
            };
            loading.set(true);
            error_msg.set(None);
            spawn_local(async move {
                match Request::get(&format!("{}/users", GATEWAY_BASE))
                    .header("Authorization", &format!("Bearer {}", token))
                    .send()
                    .await
                {
                    Ok(resp) if resp.ok() => {
                        if let Ok(data) = resp.json::<Vec<User>>().await {
                            users.set(data);
                        }
                    }
                    Ok(resp) => error_msg.set(Some(format!("Error: {}", resp.status()))),
                    Err(e) => error_msg.set(Some(format!("Network error: {:?}", e))),
                }
                loading.set(false);
            });
        }
    };

    // Fetch on mount
    {
        let fetch = fetch_users.clone();
        create_effect(move |_| {
            fetch();
        });
    }

    view! {
        <div class="card">
            <h2>"Users"
                <button
                    class="btn btn-primary"
                    style="float:right;font-size:.85rem;"
                    on:click=move |_| fetch_users()
                >"Refresh"</button>
            </h2>
            {move || error_msg.get().map(|e| view! { <p class="error">{e}</p> })}
            {move || if loading.get() {
                view! { <p>"Loading..."</p> }.into_view()
            } else {
                view! {
                    <table>
                        <thead>
                            <tr>
                                <th>"Username"</th>
                                <th>"Email"</th>
                                <th>"Roles"</th>
                                <th>"ID"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || users.get().into_iter().map(|u| {
                                view! {
                                    <tr>
                                        <td>{u.username.clone()}</td>
                                        <td>{u.email.clone()}</td>
                                        <td>
                                            {u.roles.iter().map(|r| view! {
                                                <span class="badge">{r.clone()}</span>
                                            }).collect_view()}
                                        </td>
                                        <td style="font-size:.8rem;color:#888;">{&u.id[..8]}"..."</td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                }.into_view()
            }}
        </div>
    }
}

// ────────────────────────────────────────────────────────────
// Create user form
// ────────────────────────────────────────────────────────────

#[component]
fn CreateUserForm<F: Fn() + 'static>(
    access_token: RwSignal<Option<String>>,
    on_created: F,
) -> impl IntoView {
    let username: RwSignal<String> = create_rw_signal(String::new());
    let email: RwSignal<String> = create_rw_signal(String::new());
    let error_msg: RwSignal<Option<String>> = create_rw_signal(None);
    let submitting: RwSignal<bool> = create_rw_signal(false);
    let on_created = store_value(on_created);

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let token = match access_token.get() {
            Some(t) => t,
            None => return,
        };
        let u = username.get();
        let e = email.get();
        if u.is_empty() || e.is_empty() {
            error_msg.set(Some("All fields are required".to_string()));
            return;
        }
        submitting.set(true);
        error_msg.set(None);

        spawn_local(async move {
            let body = serde_json::json!({ "username": u, "email": e });
            match Request::post(&format!("{}/users", GATEWAY_BASE))
                .header("Authorization", &format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .unwrap()
                .send()
                .await
            {
                Ok(resp) if resp.status() == 201 => {
                    on_created.with_value(|f| f());
                }
                Ok(resp) => error_msg.set(Some(format!("Error: {}", resp.status()))),
                Err(e) => error_msg.set(Some(format!("Network error: {:?}", e))),
            }
            submitting.set(false);
        });
    };

    view! {
        <div class="card" style="max-width:480px;">
            <h2>"Create User"</h2>
            <form on:submit=submit>
                <input
                    type="text"
                    placeholder="Username"
                    prop:value=move || username.get()
                    on:input=move |ev| username.set(event_target_value(&ev))
                />
                <input
                    type="email"
                    placeholder="Email"
                    prop:value=move || email.get()
                    on:input=move |ev| email.set(event_target_value(&ev))
                />
                {move || error_msg.get().map(|e| view! { <p class="error">{e}</p> })}
                <button
                    class="btn btn-primary"
                    type="submit"
                    disabled=move || submitting.get()
                >
                    {move || if submitting.get() { "Creating..." } else { "Create" }}
                </button>
            </form>
        </div>
    }
}

// ────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────

#[wasm_bindgen(start)]
pub fn main() {
    leptos::mount_to_body(App);
}
