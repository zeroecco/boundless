use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub mcp: McpConfig,

    #[serde(default)]
    pub chains: HashMap<String, ChainConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// List of broker database paths to monitor
    #[serde(default)]
    pub broker_dbs: Vec<PathBuf>,

    /// Log file locations
    #[serde(default)]
    pub log_paths: Vec<PathBuf>,

    /// Default log search time range
    #[serde(default = "default_log_search_range")]
    pub default_log_search_range: String,

    /// Maximum number of log lines to return
    #[serde(default = "default_max_log_lines")]
    pub max_log_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// RPC endpoint URL
    pub rpc_url: String,

    /// Chain ID
    pub chain_id: u64,

    /// Boundless market contract address
    pub boundless_market_address: String,

    /// Optional chain name for display
    pub name: Option<String>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            broker_dbs: vec![PathBuf::from("./broker.db")],
            log_paths: vec![
                PathBuf::from("./logs/broker.log"),
                PathBuf::from("/var/log/boundless/broker.log"),
            ],
            default_log_search_range: default_log_search_range(),
            max_log_lines: default_max_log_lines(),
        }
    }
}

fn default_log_search_range() -> String {
    "24h".to_string()
}

fn default_max_log_lines() -> usize {
    1000
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {:?}", path))?;

        // Add default chains if none specified
        let mut config = config;
        if config.chains.is_empty() {
            config.chains = Self::default_chains();
        }

        Ok(config)
    }

    /// Create default configuration
    pub fn default() -> Self {
        Self { mcp: McpConfig::default(), chains: Self::default_chains() }
    }

    /// Default chain configurations
    fn default_chains() -> HashMap<String, ChainConfig> {
        let mut chains = HashMap::new();

        // Ethereum Sepolia
        chains.insert(
            "sepolia".to_string(),
            ChainConfig {
                rpc_url: "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
                chain_id: 11155111,
                boundless_market_address: "0x7B97cb8448B069c3Dc00069211c9d1BA42F59Df6".to_string(),
                name: Some("Ethereum Sepolia".to_string()),
            },
        );

        // Base Sepolia
        chains.insert(
            "base_sepolia".to_string(),
            ChainConfig {
                rpc_url: "https://base-sepolia-rpc.publicnode.com".to_string(),
                chain_id: 84532,
                boundless_market_address: "0xef2c15a68897E15d556faD8F95a1a58076C96e44".to_string(),
                name: Some("Base Sepolia".to_string()),
            },
        );

        // Local development
        chains.insert(
            "local".to_string(),
            ChainConfig {
                rpc_url: "http://localhost:8545".to_string(),
                chain_id: 31337,
                boundless_market_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
                name: Some("Local Development".to_string()),
            },
        );

        chains
    }

    /// Get chain config by chain ID
    pub fn get_chain(&self, chain_id: u64) -> Option<&ChainConfig> {
        self.chains.values().find(|c| c.chain_id == chain_id)
    }

    /// Find the first accessible broker database
    pub fn find_broker_db(&self) -> Option<&PathBuf> {
        self.mcp.broker_dbs.iter().find(|db| db.exists())
    }

    /// Find accessible log paths
    pub fn find_log_paths(&self) -> Vec<&PathBuf> {
        self.mcp.log_paths.iter().filter(|p| p.exists()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.chains.is_empty());
        assert!(config.chains.contains_key("sepolia"));
        assert!(config.chains.contains_key("base_sepolia"));
    }

    #[test]
    fn test_load_config_from_file() -> Result<()> {
        let config_content = r#"
[mcp]
broker_dbs = ["/path/to/broker1.db", "/path/to/broker2.db"]
log_paths = ["/var/log/broker.log"]
default_log_search_range = "48h"
max_log_lines = 500

[chains.custom]
rpc_url = "http://localhost:8546"
chain_id = 12345
boundless_market_address = "0x1234567890123456789012345678901234567890"
name = "Custom Chain"
"#;

        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(config_content.as_bytes())?;

        let config = Config::from_file(temp_file.path())?;

        assert_eq!(config.mcp.broker_dbs.len(), 2);
        assert_eq!(config.mcp.default_log_search_range, "48h");
        assert_eq!(config.mcp.max_log_lines, 500);
        assert!(config.chains.contains_key("custom"));

        let custom_chain = &config.chains["custom"];
        assert_eq!(custom_chain.chain_id, 12345);
        assert_eq!(custom_chain.name.as_ref().unwrap(), "Custom Chain");

        Ok(())
    }
}
