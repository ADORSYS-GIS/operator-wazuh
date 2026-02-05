//! Command line interface for the Wazuh operator
//!
//! This binary provides CLI commands for:
//! - Running the operator
//! - Generating CRD manifests
//! - Managing clusters
//! - Debugging and diagnostics

use anyhow::Result;
use clap::Parser;
use futures::join;
use operator_core::WazuhController;
use tracing::info;
use tracing_subscriber::EnvFilter;
use std::env;

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
            let log_format = env::var("LOG_FORMAT").unwrap_or_else(|_| "plain".to_string());
            let env_filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            match log_format.as_str() {
                "json" => tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .json()
                    .init(),
                _ => tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .init(),
            }
            info!("Starting Wazuh operator in namespace: {}", namespace);

            let client = kube::Client::try_default().await?;
            let context = operator_core::controller::ControllerContext::new(client.clone());

            let indexer_controller =
                WazuhController::<operator_crds::WazuhIndexerCluster>::new(context.clone());
            let manager_controller =
                WazuhController::<operator_crds::WazuhManagerCluster>::new(context.clone());
            let dashboard_controller =
                WazuhController::<operator_crds::WazuhDashboard>::new(context.clone());
            let ca_controller = WazuhController::<operator_crds::WazuhCA>::new(context.clone());
            let manager_workload_controller =
                WazuhController::<operator_crds::WazuhManager>::new(context.clone());
            let config_controller =
                WazuhController::<operator_crds::WazuhConfig>::new(context.clone());
            let rule_controller = WazuhController::<operator_crds::WazuhRule>::new(context.clone());
            let listener_controller =
                WazuhController::<operator_crds::WazuhListener>::new(context.clone());
            let security_controller =
                WazuhController::<operator_crds::WazuhIndexerSecurity>::new(context.clone());
            let indexer_config_controller =
                WazuhController::<operator_crds::WazuhIndexerConfig>::new(context.clone());
            let indexer_backup_controller =
                WazuhController::<operator_crds::WazuhIndexerBackup>::new(context.clone());
            let manager_backup_controller =
                WazuhController::<operator_crds::WazuhManagerBackup>::new(context.clone());

            let namespace_opt = if namespace == "all" {
                None
            } else {
                Some(namespace.as_str())
            };

            info!("Initializing all controllers...");

            let (
                indexer_res,
                manager_res,
                dashboard_res,
                ca_res,
                manager_workload_res,
                config_res,
                rule_res,
                listener_res,
                security_res,
                indexer_config_res,
                indexer_backup_res,
                manager_backup_res,
            ) = join!(
                indexer_controller.run(namespace_opt),
                manager_controller.run(namespace_opt),
                dashboard_controller.run(namespace_opt),
                ca_controller.run(namespace_opt),
                manager_workload_controller.run(namespace_opt),
                config_controller.run(namespace_opt),
                rule_controller.run(namespace_opt),
                listener_controller.run(namespace_opt),
                security_controller.run(namespace_opt),
                indexer_config_controller.run(namespace_opt),
                indexer_backup_controller.run(namespace_opt),
                manager_backup_controller.run(namespace_opt),
            );

            indexer_res?;
            manager_res?;
            dashboard_res?;
            ca_res?;
            manager_workload_res?;
            config_res?;
            rule_res?;
            listener_res?;
            security_res?;
            indexer_config_res?;
            indexer_backup_res?;
            manager_backup_res?;

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
            let ca_crd = operator_crds::WazuhCA::crd();
            let manager_workload_crd = operator_crds::WazuhManager::crd();
            let rule_crd = operator_crds::WazuhRule::crd();
            let decoder_crd = operator_crds::WazuhDecoder::crd();
            let config_crd = operator_crds::WazuhConfig::crd();
            let listener_crd = operator_crds::WazuhListener::crd();
            let security_crd = operator_crds::WazuhIndexerSecurity::crd();
            let indexer_config_crd = operator_crds::WazuhIndexerConfig::crd();
            let user_crd = operator_crds::WazuhIndexerUser::crd();
            let template_crd = operator_crds::WazuhIndexerIndexTemplate::crd();
            let agent_group_crd = operator_crds::WazuhAgentGroup::crd();
            let indexer_backup_crd = operator_crds::WazuhIndexerBackup::crd();
            let manager_backup_crd = operator_crds::WazuhManagerBackup::crd();

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
                output_path.join("wazuhca.yaml"),
                serde_yaml::to_string(&ca_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhmanager.yaml"),
                serde_yaml::to_string(&manager_workload_crd)?,
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
                output_path.join("wazuhindexerconfig.yaml"),
                serde_yaml::to_string(&indexer_config_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhindexeruser.yaml"),
                serde_yaml::to_string(&user_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhindexerindextemplate.yaml"),
                serde_yaml::to_string(&template_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhagentgroup.yaml"),
                serde_yaml::to_string(&agent_group_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhindexerbackup.yaml"),
                serde_yaml::to_string(&indexer_backup_crd)?,
            )?;
            fs::write(
                output_path.join("wazuhmanagerbackup.yaml"),
                serde_yaml::to_string(&manager_backup_crd)?,
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
