//! Workload identity: tokens a CI job or a pod gets from its platform, with no
//! shared secret to hand out.
//!
//! The server side accepts them through the presets on
//! `server::JwtAuthConfig` (`github_actions`, `gitlab_ci`, `kubernetes`), each
//! registered under the fixed provider name below. [`Workload`] then reads the
//! validated claims into a typed view, so consumers match on
//! `Workload::GitHub { repository, .. }` instead of raw claim names.

use crate::common::identity::AuthIdentity;

/// Provider name of the `JwtAuthConfig::github_actions` preset.
pub const GITHUB_ACTIONS_PROVIDER: &str = "github-actions";
/// Provider name of the `JwtAuthConfig::gitlab_ci` preset.
pub const GITLAB_CI_PROVIDER: &str = "gitlab-ci";
/// Provider name of the `JwtAuthConfig::kubernetes` preset.
pub const KUBERNETES_PROVIDER: &str = "kubernetes";

/// Issuer of GitHub Actions OIDC ID tokens.
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Who a validated workload token belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Workload {
    /// A GitHub Actions job.
    GitHub {
        /// `owner/name`.
        repository: String,
        owner: String,
        /// The ref the job runs on, e.g. `refs/heads/main` or
        /// `refs/pull/42/merge`.
        git_ref: String,
        /// The triggering event, e.g. `push` or `pull_request`.
        event: String,
        /// The deployment environment, when the job uses one.
        environment: Option<String>,
    },
    /// A GitLab CI job.
    GitLab {
        /// `group/project`.
        project: String,
        namespace: String,
        git_ref: String,
        /// The pipeline source, e.g. `push` or `merge_request_event`.
        pipeline_source: String,
    },
    /// A Kubernetes pod's projected service-account token.
    Kubernetes {
        namespace: String,
        service_account: String,
    },
}

impl Workload {
    /// Reads `identity` when it came from one of the workload presets and
    /// carries the claims that preset guarantees; `None` otherwise.
    pub fn of(identity: &AuthIdentity) -> Option<Self> {
        let claim = |path: &str| identity.claim_str(path).filter(|value| !value.is_empty());
        match identity.provider.as_str() {
            GITHUB_ACTIONS_PROVIDER => Some(Self::GitHub {
                repository: claim("repository")?,
                owner: claim("repository_owner")?,
                git_ref: claim("ref").unwrap_or_default(),
                event: claim("event_name").unwrap_or_default(),
                environment: claim("environment"),
            }),
            GITLAB_CI_PROVIDER => Some(Self::GitLab {
                project: claim("project_path")?,
                namespace: claim("namespace_path")?,
                git_ref: claim("ref").unwrap_or_default(),
                pipeline_source: claim("pipeline_source").unwrap_or_default(),
            }),
            KUBERNETES_PROVIDER => Some(Self::Kubernetes {
                namespace: kubernetes_claim(identity, "namespace")?,
                service_account: kubernetes_claim(identity, "serviceaccount.name")?,
            }),
            _ => None,
        }
    }
}

/// Kubernetes nests its claims under the literal key `kubernetes.io`, which a
/// dot-path cannot address, so walk it by hand.
fn kubernetes_claim(identity: &AuthIdentity, path: &str) -> Option<String> {
    let mut current = identity.claims.get("kubernetes.io")?;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    current
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

impl AuthIdentity {
    /// See [`Workload::of`].
    pub fn workload(&self) -> Option<Workload> {
        Workload::of(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(provider: &str, claims: serde_json::Value) -> AuthIdentity {
        AuthIdentity {
            provider: provider.to_string(),
            identity: "i".to_string(),
            method: "jwt".to_string(),
            claims: match claims {
                serde_json::Value::Object(map) => map.into_iter().collect(),
                _ => Default::default(),
            },
        }
    }

    #[test]
    fn a_github_actions_token_names_its_repository_and_ref() {
        let id = identity(
            GITHUB_ACTIONS_PROVIDER,
            serde_json::json!({
                "repository": "Zondax/kache",
                "repository_owner": "Zondax",
                "ref": "refs/pull/42/merge",
                "event_name": "pull_request",
            }),
        );
        assert_eq!(
            id.workload(),
            Some(Workload::GitHub {
                repository: "Zondax/kache".into(),
                owner: "Zondax".into(),
                git_ref: "refs/pull/42/merge".into(),
                event: "pull_request".into(),
                environment: None,
            })
        );
        let with_environment = identity(
            GITHUB_ACTIONS_PROVIDER,
            serde_json::json!({
                "repository": "Zondax/kache",
                "repository_owner": "Zondax",
                "environment": "production",
            }),
        );
        assert!(matches!(
            with_environment.workload(),
            Some(Workload::GitHub { environment: Some(e), .. }) if e == "production"
        ));
    }

    #[test]
    fn a_github_token_without_a_repository_is_no_workload() {
        let id = identity(
            GITHUB_ACTIONS_PROVIDER,
            serde_json::json!({"repository_owner": "Zondax", "repository": ""}),
        );
        assert_eq!(id.workload(), None);
    }

    #[test]
    fn a_gitlab_token_names_its_project() {
        let id = identity(
            GITLAB_CI_PROVIDER,
            serde_json::json!({
                "project_path": "acme/app",
                "namespace_path": "acme",
                "ref": "main",
                "pipeline_source": "push",
            }),
        );
        assert_eq!(
            id.workload(),
            Some(Workload::GitLab {
                project: "acme/app".into(),
                namespace: "acme".into(),
                git_ref: "main".into(),
                pipeline_source: "push".into(),
            })
        );
        let partial = identity(
            GITLAB_CI_PROVIDER,
            serde_json::json!({"project_path": "acme/app"}),
        );
        assert_eq!(partial.workload(), None);
    }

    #[test]
    fn a_kubernetes_token_names_its_namespace_and_service_account() {
        let id = identity(
            KUBERNETES_PROVIDER,
            serde_json::json!({
                "kubernetes.io": {
                    "namespace": "ci",
                    "serviceaccount": {"name": "runner", "uid": "u"},
                },
            }),
        );
        assert_eq!(
            id.workload(),
            Some(Workload::Kubernetes {
                namespace: "ci".into(),
                service_account: "runner".into(),
            })
        );
        let no_account = identity(
            KUBERNETES_PROVIDER,
            serde_json::json!({"kubernetes.io": {"namespace": "ci"}}),
        );
        assert_eq!(no_account.workload(), None);
    }

    #[test]
    fn other_providers_are_no_workload() {
        let id = identity(
            "kunobi",
            serde_json::json!({"repository": "Zondax/kache", "repository_owner": "Zondax"}),
        );
        assert_eq!(id.workload(), None);
    }
}
