use kube::Client;

#[derive(Clone)]
pub struct Data {
    pub(crate) client: Client
}

impl Data {
    pub fn new(client: Client) -> Self {
        Data { client }
    }
}
