use connwatch::analysis;

#[test]
fn parses_basic_http_request() {
    let raw = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    let parsed = analysis::parse_http_request(raw, false).expect("parsed");
    assert_eq!(parsed.method.as_deref(), Some("GET"));
    assert_eq!(parsed.path.as_deref(), Some("/path"));
    assert_eq!(parsed.host.as_deref(), Some("example.com"));
    assert_eq!(parsed.user_agent.as_deref(), Some("test"));
}
