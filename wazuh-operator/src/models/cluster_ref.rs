use kube::runtime::reflector::ObjectRef;
use crate::crds::wazuh_cluster::WazuhCluster;

pub type WazuhClusterRef = ObjectRef<WazuhCluster>;