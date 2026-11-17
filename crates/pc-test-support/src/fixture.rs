use serde_json::Value;

pub fn parse_fixture(source: &str) -> serde_json::Result<Value> {
    serde_json::from_str(source)
}
