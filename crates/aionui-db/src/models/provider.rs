use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Pool visibility of a provider row (column `providers.visibility`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderVisibility {
    /// Only the owning user may see and use the provider.
    Private,
    /// Listed to and usable by every member while the shared-key service is
    /// enabled; non-owner use is metered against the shared-pool daily cap.
    Shared,
}

impl ProviderVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Shared => "shared",
        }
    }

    /// Parses the column/wire form (`"private"` / `"shared"`).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "private" => Some(Self::Private),
            "shared" => Some(Self::Shared),
            _ => None,
        }
    }
}

/// Row mapping for the `providers` table.
///
/// JSON fields (models, capabilities, model_protocols, model_enabled,
/// model_health, model_settings, bedrock_config) are stored as TEXT in SQLite and
/// deserialized by the service layer.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Provider {
    pub id: String,
    pub user_id: String,
    pub platform: String,
    pub name: String,
    pub base_url: String,
    pub api_key_encrypted: String,
    /// Pool visibility. Defaults to `private` (column added by migration 045).
    pub visibility: String,
    /// JSON array of model ID strings.
    pub models: String,
    pub enabled: bool,
    /// JSON array of capability objects.
    pub capabilities: String,
    pub context_limit: Option<i64>,
    /// JSON object: model_id -> protocol string.
    pub model_protocols: Option<String>,
    /// JSON object: model_id -> bool.
    pub model_enabled: Option<String>,
    /// JSON object: model_id -> health status object.
    pub model_health: Option<String>,
    /// JSON object: model_id -> explicit model settings.
    pub model_settings: String,
    /// JSON object: Bedrock-specific configuration.
    pub bedrock_config: Option<String>,
    /// When true, base_url is treated as a complete endpoint URL.
    /// The system will NOT append paths like /v1/chat/completions.
    pub is_full_url: bool,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
}
