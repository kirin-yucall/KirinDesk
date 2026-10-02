//! 手写最小 XML 工具（M9-DNS005，Route53 请求/响应）
//!
//! 约束：**不新增任何依赖**（quick-xml 等 crate 禁止引入，dns/Cargo.toml 不可改），
//! 而 Route53 仅需两类结构：
//! - 响应解析：按标签切分（`<HostedZone>` / `<ResourceRecordSet>` / `<ResourceRecord>`），
//!   再取子标签文本（`<Name>` / `<Type>` / `<Value>` / `<IsTruncated>` ...）；
//! - 请求构造：把记录值做 XML 实体转义后拼进 `<ChangeResourceRecordSetsRequest>`。
//!
//! 实现为最小字符串扫描：不做通用 DOM/命名空间解析，也不处理同标签嵌套
//! （Route53 响应无此结构）。标签名匹配带边界检查（`<HostedZone>` 不会误匹配
//! `<HostedZones>`）。

/// XML 实体转义（写出请求体时使用；`&` 必须先转，避免二次转义）。
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// XML 实体反转义（解析响应时使用；`&amp;` 最后替换，避免二次反转）。
pub fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// 在 `xml[pos..]` 中查找 `<tag` 开标签的起始位置，且标签名边界合法
/// （其后必须是 `>`、空白或 `/`——自闭合/属性形式；`<HostedZones>` 不匹配
/// tag=`HostedZone`）。返回绝对位置。
fn find_open(xml: &str, tag: &str, pos: usize) -> Option<usize> {
    let needle = format!("<{tag}");
    let mut from = pos;
    while let Some(rel) = xml[from..].find(&needle) {
        let start = from + rel;
        // 排除闭合标签 `</tag>`（'<' 后紧跟 '/'）。
        if xml.as_bytes()[start + 1] == b'/' {
            from = start + needle.len();
            continue;
        }
        let after = start + needle.len();
        let boundary_ok = xml[after..]
            .chars()
            .next()
            .map(|c| c == '>' || c.is_whitespace() || c == '/')
            .unwrap_or(false);
        if boundary_ok {
            return Some(start);
        }
        from = start + needle.len();
    }
    None
}

/// 提取 XML 中全部 `<tag>...</tag>` 的内容片段（不含开始/结束标签本身）。
/// 支持属性（`<tag attr="..">`）；自闭合标签（`<tag/>`）无内容、被跳过。
/// 不做同标签嵌套处理（Route53 响应无此结构）。
pub fn elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut pos = 0;
    let close = format!("</{tag}");
    while let Some(start) = find_open(xml, tag, pos) {
        let after_open = start + tag.len() + 1; // 跳过 '<' 与 tag 名，指向属性/'>'
        let Some(gt_rel) = xml[after_open..].find('>') else {
            break;
        };
        let tag_end = after_open + gt_rel; // 开标签 '>' 位置
        // 自闭合 `<tag .../>`：'/' 出现在 '>' 前 → 无内容，跳过。
        if xml[after_open..tag_end].ends_with('/') {
            pos = tag_end + 1;
            continue;
        }
        // 找匹配的 `</tag>`（同样做边界检查，防 `</HostedZones>` 误匹配）。
        let mut from = tag_end + 1;
        let mut found_close = false;
        while let Some(crel) = xml[from..].find(&close) {
            let close_start = from + crel;
            let after_close = close_start + close.len();
            let boundary_ok = xml[after_close..]
                .chars()
                .next()
                .map(|c| c == '>' || c.is_whitespace())
                .unwrap_or(false);
            if boundary_ok {
                out.push(&xml[tag_end + 1..close_start]);
                pos = after_close + 1;
                found_close = true;
                break;
            }
            from = close_start + close.len();
        }
        // 找不到闭合标签 → 视为输入截断，停止扫描。
        if !found_close {
            break;
        }
    }
    out
}

/// 取片段中第一个 `<tag>...</tag>` 的文本（去首尾空白并反转义）。
pub fn element_text(xml: &str, tag: &str) -> Option<String> {
    elements(xml, tag)
        .first()
        .map(|s| unescape(s.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <HostedZones>
    <HostedZone>
      <Id>/hostedzone/Z1PA6795UKMFR9</Id>
      <Name>example.com.</Name>
      <CallerReference>abc123</CallerReference>
      <Config><PrivateZone>false</PrivateZone></Config>
      <ResourceRecordSetCount>3</ResourceRecordSetCount>
    </HostedZone>
    <HostedZone>
      <Id>/hostedzone/Z2XYZ</Id>
      <Name>kirin.dev.</Name>
    </HostedZone>
  </HostedZones>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListHostedZonesResponse>"#;

    const RRSETS_XML: &str = r#"<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>example.com.</Name>
      <Type>A</Type>
      <TTL>600</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>192.0.2.1</Value></ResourceRecord>
        <ResourceRecord><Value>192.0.2.2</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
    <ResourceRecordSet>
      <Name>_sip._tcp.example.com.</Name>
      <Type>SRV</Type>
      <TTL>60</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>0 5 5060 sip.example.com.</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>true</IsTruncated>
  <NextRecordName>_sip._tcp.example.com.</NextRecordName>
  <NextRecordType>SRV</NextRecordType>
</ListResourceRecordSetsResponse>"#;

    #[test]
    fn escape_and_unescape_roundtrip() {
        assert_eq!(escape("a<b&c>\"d'e"), "a&lt;b&amp;c&gt;&quot;d&apos;e");
        assert_eq!(unescape("a&lt;b&amp;c&gt;&quot;d&apos;e"), "a<b&c>\"d'e");
        // 无实体内容保持原样。
        assert_eq!(unescape("hello world"), "hello world");
    }

    #[test]
    fn parse_hosted_zones() {
        let zones = elements(ZONES_XML, "HostedZone");
        assert_eq!(zones.len(), 2);
        let first = zones[0];
        assert_eq!(element_text(first, "Id").as_deref(), Some("/hostedzone/Z1PA6795UKMFR9"));
        assert_eq!(element_text(first, "Name").as_deref(), Some("example.com."));
        assert_eq!(element_text(first, "ResourceRecordSetCount").as_deref(), Some("3"));
        let second = zones[1];
        assert_eq!(element_text(second, "Name").as_deref(), Some("kirin.dev."));
        // 顶层分页标记。
        assert_eq!(element_text(ZONES_XML, "IsTruncated").as_deref(), Some("false"));
        // 边界检查：`<HostedZones>` 不应被 `HostedZone` 匹配。
        assert_eq!(elements(ZONES_XML, "HostedZones").len(), 1);
    }

    #[test]
    fn parse_resource_record_sets() {
        let sets = elements(RRSETS_XML, "ResourceRecordSet");
        assert_eq!(sets.len(), 2);

        let a = sets[0];
        assert_eq!(element_text(a, "Name").as_deref(), Some("example.com."));
        assert_eq!(element_text(a, "Type").as_deref(), Some("A"));
        assert_eq!(element_text(a, "TTL").as_deref(), Some("600"));
        let values: Vec<String> = elements(a, "ResourceRecord")
            .iter()
            .filter_map(|rr| element_text(rr, "Value"))
            .collect();
        assert_eq!(values, vec!["192.0.2.1", "192.0.2.2"]);

        let srv = sets[1];
        assert_eq!(element_text(srv, "Type").as_deref(), Some("SRV"));
        // SRV 单值字符串："priority weight port target."（无字面引号）。
        let v = element_text(srv, "Value");
        assert_eq!(v.as_deref(), Some("0 5 5060 sip.example.com."));

        // 分页标记。
        assert_eq!(element_text(RRSETS_XML, "IsTruncated").as_deref(), Some("true"));
        assert_eq!(element_text(RRSETS_XML, "NextRecordName").as_deref(), Some("_sip._tcp.example.com."));
        assert_eq!(element_text(RRSETS_XML, "NextRecordType").as_deref(), Some("SRV"));
    }

    #[test]
    fn parse_error_response_code() {
        let err_xml = r#"<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Error>
    <Type>Sender</Type>
    <Code>NoSuchHostedZone</Code>
    <Message>No hosted zone found with ID: Z123</Message>
  </Error>
  <RequestId>abc</RequestId>
</ErrorResponse>"#;
        assert_eq!(element_text(err_xml, "Code").as_deref(), Some("NoSuchHostedZone"));
        assert_eq!(element_text(err_xml, "Message").as_deref(), Some("No hosted zone found with ID: Z123"));
    }

    #[test]
    fn empty_or_absent_tag() {
        assert!(elements("", "Name").is_empty());
        assert!(element_text("<A>1</A>", "Name").is_none());
        // 标签存在但内容为空 → 空串；标签缺失 → None。
        assert_eq!(element_text("<Name></Name>", "Name").as_deref(), Some(""));
        assert_eq!(element_text("<Name>x</Name>", "Name").as_deref(), Some("x"));
    }
}
