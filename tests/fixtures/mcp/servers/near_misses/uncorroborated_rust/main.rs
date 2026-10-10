struct Counter;

impl ServerHandler for Counter {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}
