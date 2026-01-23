use serde::Deserialize;
use std::fs;
use std::path::Path;
use url::Url;

const ENV_CONFIG_PATH: &str = "DA_AGENT_CONFIG_PATH";
const DEFAULT_CONFIG_PATH: &str = "config.yaml";

/// Retriever filtering configuration
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RetrieverConfig {
    /// Allowed domains (whitelist). If empty, all domains are allowed.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Denied domains (blacklist). Applied after allow list.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl RetrieverConfig {
    /// Check if a URL is allowed based on the allow/deny lists
    pub fn is_url_allowed(&self, url: &Url) -> bool {
        let host = match url.host_str() {
            Some(h) => h.to_lowercase(),
            None => return false,
        };

        // If deny list contains the host, reject
        if self.deny.iter().any(|d| host.contains(&d.to_lowercase())) {
            return false;
        }

        // If allow list is empty, allow all (except denied)
        if self.allow.is_empty() {
            return true;
        }

        // Otherwise, check if host matches any allow pattern
        self.allow.iter().any(|a| host.contains(&a.to_lowercase()))
    }
}

/// YAML configuration file structure
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub retrievers: RetrieverConfig,
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub retrievers: RetrieverConfig,
    pub port: u16,
    pub host: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            retrievers: RetrieverConfig::default(),
            port: 8080,
            host: "127.0.0.1".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from environment and config file
    pub fn from_env() -> Self {
        let port = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);

        let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

        // Load config file
        let config_path = std::env::var(ENV_CONFIG_PATH)
            .unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());

        let retrievers = Self::load_config_file(&config_path)
            .map(|cf| cf.retrievers)
            .unwrap_or_default();

        Self {
            retrievers,
            port,
            host,
        }
    }

    /// Load configuration from YAML file
    fn load_config_file(path: &str) -> Option<ConfigFile> {
        let path = Path::new(path);

        if !path.exists() {
            tracing::debug!(path = %path.display(), "Config file not found, using defaults");
            return None;
        }

        match fs::read_to_string(path) {
            Ok(contents) => {
                // Handle empty file
                let contents = contents.trim();
                if contents.is_empty() {
                    tracing::debug!(path = %path.display(), "Config file is empty, using defaults");
                    return Some(ConfigFile::default());
                }

                match serde_yaml::from_str(contents) {
                    Ok(config) => {
                        tracing::info!(path = %path.display(), "Loaded configuration from file");
                        Some(config)
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "Failed to parse config file, using defaults");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Failed to read config file, using defaults");
                None
            }
        }
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
