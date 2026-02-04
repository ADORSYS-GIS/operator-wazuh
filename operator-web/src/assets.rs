//! Static assets for the web UI
//!
//! This module provides embedded static files for the web interface.

pub struct Assets;

impl Assets {
    /// Get the index.html content
    pub fn index() -> &'static str {
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wazuh Operator</title>
</head>
<body>
    <div id="app">
        <h1>Wazuh Operator Dashboard</h1>
        <p>Web interface will be implemented here</p>
    </div>
</body>
</html>"#
    }
}
