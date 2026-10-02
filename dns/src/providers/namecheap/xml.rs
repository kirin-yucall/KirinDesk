//! M9-DNS009: Namecheap 响应手写 XML 解析（不新增 XML 依赖）
//!
//! 覆盖 Namecheap API 响应所需子集：
//! - 根元素 `<ApiResponse Status="OK|ERROR" xmlns="...">`
//! - `<Errors><Error Number="1011002">消息</Error></Errors>`
//! - `<DomainGetListResult><Domain Name="example.com" .../></DomainGetListResult>`
//! - `<DomainDNSGetHostsResult Domain= IsUsingOurDNS=><host HostId= Name= Type=
//!   Address= MXPref= TTL=/>...</DomainDNSGetHostsResult>`
//! - `<DomainDNSSetHostsResult Domain= IsSuccess=/>`
//! - SRV（未公开命令）：`<CommandResponse><Result><Records><Service/>...
//!   </Records>...</Result></CommandResponse>`（空 zone 时无 `<Result>`，兼容）
//!
//! 解析器特性：命名空间前缀剥离、属性、自闭合标签、注释、CDATA、
//! 实体解码（`&amp;` `&lt;` `&gt;` `&quot;` `&apos;` 及数字实体）。

use crate::provider::ProviderError;

/// 极简 XML 节点。
#[derive(Debug, Clone)]
pub(crate) struct XmlNode {
    /// 元素本地名（命名空间前缀已剥离，如 "ApiResponse"）。
    pub name: String,
    /// 属性（保序，如 [("Status", "OK")]）。
    pub attrs: Vec<(String, String)>,
    /// 子元素。
    pub children: Vec<XmlNode>,
    /// 文本内容（已解码实体；不含子元素的文本）。
    pub text: String,
}

impl XmlNode {
    /// 读取属性（精确匹配，Namecheap 属性名大小写敏感）。
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// 第一个同名子元素。
    pub fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// 全部同名子元素。
    pub fn children_named(&self, name: &str) -> Vec<&XmlNode> {
        self.children.iter().filter(|c| c.name == name).collect()
    }

    /// 任意深度（含自身）第一个同名节点。
    pub fn find_descendant(&self, name: &str) -> Option<&XmlNode> {
        if self.name == name {
            return Some(self);
        }
        for c in &self.children {
            if let Some(n) = c.find_descendant(name) {
                return Some(n);
            }
        }
        None
    }

    /// 任意深度（含自身）收集全部同名节点（SRV `<Records>` 层级不固定时使用）。
    pub fn descendants_named<'a>(&'a self, name: &'a str) -> Vec<&'a XmlNode> {
        let mut out = Vec::new();
        self.collect_desc(name, &mut out);
        out
    }

    fn collect_desc<'a>(&'a self, name: &str, out: &mut Vec<&'a XmlNode>) {
        if self.name == name {
            out.push(self);
        }
        for c in &self.children {
            c.collect_desc(name, out);
        }
    }
}

/// Namecheap 错误条目（`<Error Number="..">消息</Error>`）。
#[derive(Debug, Clone)]
pub(crate) struct NcError {
    pub number: u32,
    pub message: String,
}

/// getHosts 的 host 元素（属性：HostId/Name/Type/Address/MXPref/TTL）。
#[derive(Debug, Clone)]
pub(crate) struct NcHost {
    pub name: String,
    pub rtype: String,
    pub address: String,
    pub mxpref: u16,
    pub ttl: u32,
}

/// getsrvrecords 的单条 SRV（子元素：Service/Protocol/Priority/Port/Target/Weight）。
#[derive(Debug, Clone)]
pub(crate) struct NcSrvRecord {
    pub service: String,
    pub protocol: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// 解析后的 API 响应（各命令按需填充；未命中的命令字段为空）。
#[derive(Debug, Default)]
pub(crate) struct NcApiResponse {
    /// 根属性 Status："OK" / "ERROR"。
    pub status: String,
    /// getList：域名列表。
    pub domains: Vec<String>,
    /// getList：Paging>TotalItems（分页终止判断用；缺省 0 = 未知）。
    pub total_items: u32,
    /// getHosts：host 列表。
    pub hosts: Vec<NcHost>,
    /// getsrvrecords：SRV 列表。
    pub srv_records: Vec<NcSrvRecord>,
    /// 业务错误列表。
    pub errors: Vec<NcError>,
    /// setHosts：IsSuccess 属性。
    pub set_hosts_ok: bool,
}

/// 解析 Namecheap API 响应 XML。
pub(crate) fn parse_api_response(xml: &str) -> Result<NcApiResponse, ProviderError> {
    let root = parse(xml)?;
    let mut out = NcApiResponse::default();
    out.status = root.attr("Status").unwrap_or("").to_string();

    // <Errors><Error Number="1011002">msg</Error></Errors>
    if let Some(errors_el) = root.find_descendant("Errors") {
        for e in errors_el.children_named("Error") {
            let number = e.attr("Number").and_then(|n| n.parse().ok()).unwrap_or(0);
            out.errors.push(NcError {
                number,
                message: e.text.trim().to_string(),
            });
        }
    }

    // getList：<DomainGetListResult><Domain Name=".." .../></DomainGetListResult>
    if let Some(result) = root.find_descendant("DomainGetListResult") {
        for d in result.children_named("Domain") {
            if let Some(n) = d.attr("Name") {
                out.domains.push(n.to_string());
            }
        }
    }

    // getList 分页：<Paging><TotalItems>N</TotalItems></Paging>
    if let Some(paging) = root.find_descendant("Paging") {
        if let Some(t) = paging.child("TotalItems") {
            out.total_items = t.text.trim().parse().unwrap_or(0);
        }
    }

    // getHosts：<DomainDNSGetHostsResult><host Name= Type= Address= MXPref= TTL=/></DomainDNSGetHostsResult>
    if let Some(hosts_el) = root.find_descendant("DomainDNSGetHostsResult") {
        for h in hosts_el.children_named("host") {
            out.hosts.push(NcHost {
                name: h.attr("Name").unwrap_or("").to_string(),
                rtype: h.attr("Type").unwrap_or("").to_string(),
                address: h.attr("Address").unwrap_or("").to_string(),
                mxpref: h.attr("MXPref").and_then(|v| v.parse().ok()).unwrap_or(0),
                ttl: h.attr("TTL").and_then(|v| v.parse().ok()).unwrap_or(0),
            });
        }
    }

    // setHosts：<DomainDNSSetHostsResult Domain= IsSuccess="true"/>
    if let Some(sh) = root.find_descendant("DomainDNSSetHostsResult") {
        out.set_hosts_ok = sh
            .attr("IsSuccess")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    }

    // getsrvrecords：<CommandResponse><Result><Records><Service/>...<Weight/></Records>...</Result></CommandResponse>
    // （空 zone 时响应不含 <Result>，兼容为空列表；层级不确定 → 任意深度找 <Records>）
    for rec_el in root.descendants_named("Records") {
        out.srv_records.push(NcSrvRecord {
            service: text_of(rec_el, "Service"),
            protocol: text_of(rec_el, "Protocol"),
            priority: num_of(rec_el, "Priority"),
            weight: num_of(rec_el, "Weight"),
            port: num_of(rec_el, "Port"),
            target: text_of(rec_el, "Target"),
        });
    }

    Ok(out)
}

/// 子元素文本（trim）。
fn text_of(node: &XmlNode, child: &str) -> String {
    node.child(child)
        .map(|n| n.text.trim().to_string())
        .unwrap_or_default()
}

/// 子元素数字（缺省 0）。
fn num_of(node: &XmlNode, child: &str) -> u16 {
    node.child(child)
        .and_then(|n| n.text.trim().parse().ok())
        .unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────
// 手写 XML 解析器
// ────────────────────────────────────────────────────────────────

/// 解析 XML 文档，返回根元素节点。
pub(crate) fn parse(xml: &str) -> Result<XmlNode, ProviderError> {
    let mut p = Parser {
        chars: xml.chars().collect(),
        pos: 0,
    };
    p.parse_document()
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn starts_with(&self, s: &str) -> bool {
        let rest: String = self.chars[self.pos..].iter().collect();
        rest.starts_with(s)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.pos += 1;
        }
    }

    fn parse_document(&mut self) -> Result<XmlNode, ProviderError> {
        // 跳过 prolog / 注释 / doctype，找到第一个元素。
        loop {
            self.skip_ws();
            match self.peek() {
                None => return Err(err("XML 缺少根元素")),
                Some('<') if self.starts_with("<?") || self.starts_with("<!") => {
                    self.skip_declaration()?;
                }
                Some('<') => break,
                Some(_) => return Err(err("XML 根元素之前存在非空白文本")),
            }
        }
        self.parse_element()
    }

    /// 跳过 `<?...?>` / `<!--...-->` / `<!...>` 声明块。
    fn skip_declaration(&mut self) -> Result<(), ProviderError> {
        if self.starts_with("<!--") {
            while self.pos < self.chars.len() && !self.starts_with("-->") {
                self.pos += 1;
            }
            self.pos = (self.pos + 3).min(self.chars.len());
            return Ok(());
        }
        while self.pos < self.chars.len() {
            if self.peek() == Some('>') {
                self.pos += 1;
                return Ok(());
            }
            self.pos += 1;
        }
        Err(err("XML 声明未闭合"))
    }

    fn expect(&mut self, c: char) -> Result<(), ProviderError> {
        match self.bump() {
            Some(x) if x == c => Ok(()),
            _ => Err(err(format!("期望字符 '{c}'"))),
        }
    }

    /// 标签/属性名；遇空白、'/'、'>'、'=' 停止；剥离命名空间前缀。
    fn parse_name(&mut self) -> Result<String, ProviderError> {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_whitespace() || c == '/' || c == '>' || c == '=' {
                break;
            }
            s.push(c);
            self.pos += 1;
        }
        if s.is_empty() {
            return Err(err("XML 缺少标签名/属性名"));
        }
        Ok(match s.split_once(':') {
            Some((_, local)) => local.to_string(),
            None => s,
        })
    }

    fn parse_attr(&mut self) -> Result<(String, String), ProviderError> {
        let key = self.parse_name()?;
        self.skip_ws();
        self.expect('=')?;
        self.skip_ws();
        let quote = self.bump().ok_or_else(|| err("属性值缺少引号"))?;
        if quote != '"' && quote != '\'' {
            return Err(err("属性值引号非法"));
        }
        let mut val = String::new();
        loop {
            match self.bump() {
                Some(c) if c == quote => break,
                Some(c) => val.push(c),
                None => return Err(err("属性值未闭合")),
            }
        }
        Ok((key, decode_entities(&val)))
    }

    fn parse_element(&mut self) -> Result<XmlNode, ProviderError> {
        debug_assert_eq!(self.peek(), Some('<'));
        self.pos += 1; // 消费 '<'
        let name = self.parse_name()?;
        let mut attrs = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some('/') => {
                    // 自闭合 <name .../>
                    self.pos += 1;
                    self.expect('>')?;
                    return Ok(XmlNode {
                        name,
                        attrs,
                        children: Vec::new(),
                        text: String::new(),
                    });
                }
                Some('>') => {
                    self.pos += 1;
                    break;
                }
                Some(_) => attrs.push(self.parse_attr()?),
                None => return Err(err(format!("元素 <{name}> 未闭合"))),
            }
        }
        // 内容：文本 + 子元素。
        let mut text = String::new();
        let mut children = Vec::new();
        loop {
            match self.peek() {
                None => return Err(err(format!("元素 <{name}> 未闭合"))),
                Some('<') if self.starts_with("</") => {
                    self.pos += 2;
                    let close = self.parse_name()?;
                    self.skip_ws();
                    self.expect('>')?;
                    if close != name {
                        return Err(err(format!(
                            "结束标签 </{close}> 与开始标签 <{name}> 不匹配"
                        )));
                    }
                    break;
                }
                Some('<') if self.starts_with("<!--") => self.skip_declaration()?,
                Some('<') if self.starts_with("<![CDATA[") => {
                    self.pos += "<![CDATA[".len();
                    let end = self.find_str("]]>")?;
                    text.push_str(&self.chars[self.pos..end].iter().collect::<String>());
                    self.pos = end + 3;
                }
                Some('<') if self.starts_with("<?") || self.starts_with("<!") => {
                    self.skip_declaration()?;
                }
                Some('<') => children.push(self.parse_element()?),
                Some(c) => {
                    text.push(c);
                    self.pos += 1;
                }
            }
        }
        Ok(XmlNode {
            name,
            attrs,
            children,
            text: decode_entities(&text),
        })
    }

    fn find_str(&self, needle: &str) -> Result<usize, ProviderError> {
        let s: String = self.chars[self.pos..].iter().collect();
        s.find(needle)
            .map(|i| self.pos + i)
            .ok_or_else(|| err(format!("缺少结束标记 {needle}")))
    }
}

fn err(msg: impl Into<String>) -> ProviderError {
    ProviderError::Other(format!("Namecheap XML 解析失败: {}", msg.into()))
}

/// 解码 XML 实体（&amp; &lt; &gt; &quot; &apos; &nbsp; 与数字实体）。
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if let Some(end) = tail.find(';') {
            let ent = &tail[1..end];
            if let Some(ch) = decode_entity(ent) {
                out.push(ch);
                rest = &tail[end + 1..];
                continue;
            }
        }
        // 未识别的实体：按字面保留。
        out.push('&');
        rest = &tail[1..];
    }
    out.push_str(rest);
    out
}

fn decode_entity(e: &str) -> Option<char> {
    match e {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{00A0}'),
        _ => {
            if let Some(hex) = e.strip_prefix("#x").or_else(|| e.strip_prefix("#X")) {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else if let Some(dec) = e.strip_prefix('#') {
                dec.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    /// 解析器基础用例：命名空间、自闭合、实体。
    #[test]
    fn parses_attributes_entities_and_ns() {
        let root = parse(
            r#"<?xml version="1.0"?>
            <ns:ApiResponse Status="OK" xmlns:ns="http://api.namecheap.com/xml.response">
              <Errors/>
              <CommandResponse Type="x">
                <DomainGetListResult>
                  <Domain Name="a.com" Note="a&amp;b &lt;c&gt; &#65;"/>
                </DomainGetListResult>
              </CommandResponse>
            </ns:ApiResponse>"#,
        )
        .unwrap();
        assert_eq!(root.name, "ApiResponse");
        assert_eq!(root.attr("Status"), Some("OK"));
        let result = root.find_descendant("DomainGetListResult").unwrap();
        let d = result.children_named("Domain")[0];
        assert_eq!(d.attr("Name"), Some("a.com"));
        assert_eq!(d.attr("Note"), Some("a&b <c> A"));
    }

    #[test]
    fn parses_text_with_cdata() {
        let root = parse("<r><t>hello <![CDATA[<raw> & stuff]]> world</t></r>").unwrap();
        assert_eq!(root.child("t").unwrap().text, "hello <raw> & stuff world");
    }

    #[test]
    fn mismatched_close_reports_error() {
        assert!(parse("<a><b></a></b>").is_err());
        assert!(parse("<a").is_err());
    }
}
