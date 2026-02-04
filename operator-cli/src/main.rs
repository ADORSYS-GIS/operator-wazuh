//! Command line interface for the Wazuh operator
//!
//! This binary provides CLI commands for:
//! - Running the operator
//! - Generating CRD manifests
//! - Managing clusters
//! - Debugging and diagnostics

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "wazuh-operator")]
#[command(about = "A Kubernetes operator for managing Wazuh clusters")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Parser)]
pub enum Commands {
    /// Run the operator controller
    Run {
        #[arg(short, long, default_value = "default")]
        namespace: String,
    },
    /// Generate CRD YAML manifests
    GenerateCrd {
        #[arg(short, long, default_value = "./manifests/crds")]
        output_dir: String,
    },
    /// Validate cluster configuration
    Validate {
        #[arg(short, long)]
        config_file: String,
    },
    /// Inspect CRD status
    Inspect {
        #[arg(short, long)]
        kind: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value = "default")]
        namespace: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { namespace } => {
            println!("Starting Wazuh operator in namespace: {}", namespace);
            // TODO: Implement operator runtime
            Ok(())
        }
        Commands::GenerateCrd { output_dir } => {
            use kube::CustomResourceExt;
            use std::fs;
            use std::path::Path;

            println!("Generating CRD manifests to: {}", output_dir);

            let output_path = Path::new(&output_dir);
            if !output_path.exists() {
                fs::create_dir_all(output_path)?;
            }

            let indexer_crd = operator_crds::WazuhIndexerCluster::crd();
            let manager_crd = operator_crds::WazuhManagerCluster::crd();
            let dashboard_crd = operator_crds::WazuhDashboard::crd();
            let rule_crd = operator_crds::WazuhRule::crd();
            let decoder_crd = operator_crds::WazuhDecoder::crd();
            let config_crd = operator_crds::WazuhConfig::crd();
            let listener_crd = operator_crds::WazuhListener::crd();
            let security_crd = operator_crds::WazuhIndexerSecurity::crd();
            let user_crd = operator_crds::WazuhIndexerUser::crd();
            let template_crd = operator_crds::WazuhIndexerIndexTemplate::crd();

            fs::write(
                output_path.join("wazuhindexercluster.yaml"),
                serde_yaml::to_string(&indexer_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhmanagercluster.yaml"),
                serde_yaml::to_string(&manager_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhdashboard.yaml"),
                serde_yaml::to_string(&dashboard_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhrule.yaml"),
                serde_yaml::to_string(&rule_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhdecoder.yaml"),
                serde_yaml::to_string(&decoder_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhconfig.yaml"),
                serde_yaml::to_string(&config_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhlistener.yaml"),
                serde_yaml::to_string(&listener_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhindexersecurity.yaml"),
                serde_yaml::to_string(&security_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhindexeruser.yaml"),
                serde_yaml::to_string(&user_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhindexerindextemplate.yaml"),
                serde_yaml::to_string(&template_crd)?,
            )?;

            println!("Successfully generated CRD manifests.");
            Ok(())
        }
        Commands::Validate { config_file } => {
            println!("Validating configuration: {}", config_file);
            // TODO: Implement validation
            Ok(())
        }
        Commands::Inspect {
            kind,
            name,
            namespace,
        } => {
            println!("Inspecting {}/{} in namespace {}", kind, name, namespace);
            // TODO: Implement inspection logic using kube-rs
            Ok(())
        }
    }
}
