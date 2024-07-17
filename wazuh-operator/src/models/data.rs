use kube::Client;

#[derive(Clone)]
pub struct Data {
    client: Client
}

impl Data {
    pub fn new(client: Client) -> Self {
        Data { client }
    }
}
