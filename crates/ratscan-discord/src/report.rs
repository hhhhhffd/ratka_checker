use ratscan_models::scan::{ConfirmedChain, Finding, ScanResponse, Severity};

pub const MAX_EMBED_FIELDS: usize = 25;
pub const MAX_FIELD_CHARS: usize = 1024;
pub const MAX_DESCRIPTION_CHARS: usize = 4096;
pub const MAX_EMBED_CHARS: usize = 6000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportContext {
    pub filename: String,
    pub author_id: u64,
    pub channel_id: u64,
    pub thread_url: String,
    pub coverage_warning_threshold: u8,
    pub report_virustotal: bool,
    pub report_behavior: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportEmbed {
    pub title: String,
    pub description: String,
    pub fields: Vec<ReportField>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportField {
    pub name: String,
    pub value: String,
}

/// Renders the complete API response. Verdict is intentionally displayed verbatim from the API.
pub fn format_report(result: &ScanResponse, context: &ReportContext) -> Vec<ReportEmbed> {
    let mut fields = vec![
        ReportField {
            name: "Summary".into(),
            value: summary(result, context),
        },
        ReportField {
            name: "Confirmed chains".into(),
            value: chains(result),
        },
        ReportField {
            name: "Findings".into(),
            value: findings(&result.findings),
        },
        ReportField {
            name: "Capabilities (neutral)".into(),
            value: capabilities(result),
        },
        ReportField {
            name: "Obfuscation".into(),
            value: format!(
                "Complexity of analysis: {:?}, score {}/100.",
                result.obfuscation.level, result.obfuscation.score
            ),
        },
        ReportField {
            name: "Limitations".into(),
            value: limitations(result, context.coverage_warning_threshold),
        },
    ];
    if context.report_virustotal {
        fields.push(ReportField {
            name: "VirusTotal detections".into(),
            value: virustotal(result),
        });
    }
    if context.report_behavior {
        fields.push(ReportField {
            name: "Sandbox behavior (attributed)".into(),
            value: behavior(result),
        });
    }
    split_embeds("RatScan report", fields)
}

fn summary(result: &ScanResponse, context: &ReportContext) -> String {
    format!(
        "Verdict: **{}**\nRisk: {}/100\nConfidence: {:?}\nCoverage: {}/100\nSHA-256: `{}`\nFile: `{}`\nAuthor: <@{}>\nChannel: <#{}>\nThread: {}",
        result.verdict.as_ref().map_or("unknown", |value| match value { ratscan_models::scan::Verdict::Clean => "clean", ratscan_models::scan::Verdict::Suspicious => "suspicious", ratscan_models::scan::Verdict::Malicious => "malicious", ratscan_models::scan::Verdict::Unknown => "unknown" }),
        result.risk_score, result.confidence, result.analysis_coverage.overall_score, result.sha256, escape(&context.filename), context.author_id, context.channel_id, context.thread_url,
    )
}

fn chains(result: &ScanResponse) -> String {
    if result.confirmed_chains.is_empty() {
        return "No confirmed chains.".into();
    }
    let mut chains = result.confirmed_chains.clone();
    chains.sort_by_key(|chain| std::cmp::Reverse(severity_rank(&chain.severity)));
    chains
        .into_iter()
        .map(format_chain)
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn format_chain(chain: ConfirmedChain) -> String {
    let evidence = chain
        .evidence
        .first()
        .map(|value| {
            format!(
                "scope={:?}; {}/{}/{}",
                value.scope,
                value.archive_path,
                value.class_name.as_deref().unwrap_or("-"),
                value.method_name.as_deref().unwrap_or("-")
            )
        })
        .unwrap_or_else(|| "no evidence location".into());
    format!(
        "`{}` · {:?} · {:?} · +{}\n{}\n{}",
        chain.rule_id,
        chain.severity,
        chain.confidence,
        chain.score_contribution,
        chain.operations.join(" → "),
        evidence
    )
}

fn findings(values: &[Finding]) -> String {
    if values.is_empty() {
        return "No findings.".into();
    }
    values
        .iter()
        .map(|value| {
            let evidence = value
                .evidence
                .first()
                .map(|e| format!("; scope={:?}; {}", e.scope, e.archive_path))
                .unwrap_or_default();
            format!(
                "`{}` · kind={:?} · {:?} · +{}\n{}{}",
                value.rule_id,
                value.kind,
                value.severity,
                value.score_contribution,
                escape(&value.message),
                evidence
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn capabilities(result: &ScanResponse) -> String {
    if result.capabilities.is_empty() {
        return "No neutral capabilities reported.".into();
    }
    result
        .capabilities
        .iter()
        .map(|value| format!("`{}` — {}", value.rule_id, escape(&value.message)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn limitations(result: &ScanResponse, threshold: u8) -> String {
    let warning =
        result.analysis_coverage.overall_score < threshold || !result.limitations.is_empty();
    let mut lines = if warning {
        vec!["⚠️ Файл не признан вредоносным, но анализ выполнен не полностью.".to_owned()]
    } else {
        Vec::new()
    };
    if result.limitations.is_empty() {
        lines.push("No reported limitations.".into());
    }
    lines.extend(
        result
            .limitations
            .iter()
            .map(|value| format!("`{}` — {}", value.code, escape(&value.message))),
    );
    lines.join("\n")
}

fn virustotal(result: &ScanResponse) -> String {
    let Some(report) = &result.virustotal else {
        return "No VirusTotal data.".into();
    };
    let Some(stats) = &report.stats else {
        return "VirusTotal did not return detection statistics.".into();
    };
    let engines = report
        .flagged_engines
        .iter()
        .map(|engine| {
            format!(
                "{}: {}",
                engine.engine_name,
                engine.result.as_deref().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "malicious={}, suspicious={}, engines: {}",
        stats.malicious,
        stats.suspicious,
        if engines.is_empty() { "none" } else { &engines }
    )
}

fn behavior(result: &ScanResponse) -> String {
    let Some(behavior) = result
        .virustotal
        .as_ref()
        .and_then(|report| report.behavior.as_ref())
    else {
        return "No sandbox behavior data.".into();
    };
    let attributed = behavior
        .attributed_network
        .iter()
        .filter_map(|item| item.domain.as_deref().or(item.url.as_deref()))
        .collect::<Vec<_>>()
        .join(", ");
    let noise = if behavior.environment_noise.is_empty() {
        "none".into()
    } else {
        behavior.environment_noise.join(", ")
    };
    format!(
        "Attributed sample behavior: {}\nEnvironment noise (not attributed to file): {}",
        if attributed.is_empty() {
            "none"
        } else {
            &attributed
        },
        noise
    )
}

fn split_embeds(title: &str, fields: Vec<ReportField>) -> Vec<ReportEmbed> {
    let mut embeds = Vec::new();
    let mut current = ReportEmbed {
        title: title.into(),
        description: String::new(),
        fields: Vec::new(),
    };
    let mut size = title.len();
    for field in fields {
        for value in chunks(&field.value, MAX_FIELD_CHARS) {
            let part = ReportField {
                name: if current.fields.iter().any(|item| item.name == field.name) {
                    format!("{} (continued)", field.name)
                } else {
                    field.name.clone()
                },
                value,
            };
            let part_size = part.name.len() + part.value.len();
            if current.fields.len() == MAX_EMBED_FIELDS || size + part_size > MAX_EMBED_CHARS {
                embeds.push(current);
                current = ReportEmbed {
                    title: format!("{} (continued)", title),
                    description: String::new(),
                    fields: Vec::new(),
                };
                size = current.title.len();
            }
            size += part_size;
            current.fields.push(part);
        }
    }
    if !current.fields.is_empty() {
        embeds.push(current);
    }
    embeds
}

fn chunks(value: &str, limit: usize) -> Vec<String> {
    if value.is_empty() {
        return vec!["—".into()];
    }
    let mut values = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let mut end = (start + limit).min(value.len());
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        values.push(value[start..end].to_owned());
        start = end;
    }
    values
}

fn severity_rank(value: &Severity) -> u8 {
    match value {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}
fn escape(value: &str) -> String {
    value.replace('`', "'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratscan_models::scan::{
        AnalysisCoverage, Confidence, Obfuscation, ObfuscationLevel, ScanStatus,
    };
    use uuid::Uuid;

    fn response() -> ScanResponse {
        ScanResponse {
            scan_id: Uuid::nil(),
            status: ScanStatus::Done,
            sha256: "hash".into(),
            verdict: Some(ratscan_models::scan::Verdict::Clean),
            risk_score: 0,
            confidence: Confidence::High,
            obfuscation_score: 0,
            analysis_coverage: AnalysisCoverage {
                overall_score: 50,
                ..Default::default()
            },
            capabilities: vec![],
            decoded_strings: vec![],
            text_resources: vec![],
            findings: vec![],
            confirmed_chains: vec![],
            obfuscation: Obfuscation {
                level: ObfuscationLevel::None,
                score: 0,
                signals: vec![],
            },
            limitations: vec![],
            virustotal: None,
        }
    }
    fn context() -> ReportContext {
        ReportContext {
            filename: "a.jar".into(),
            author_id: 1,
            channel_id: 2,
            thread_url: "thread".into(),
            coverage_warning_threshold: 80,
            report_virustotal: false,
            report_behavior: false,
        }
    }

    #[test]
    fn clean_low_coverage_has_limitation_warning() {
        assert!(format_report(&response(), &context())
            .iter()
            .flat_map(|embed| &embed.fields)
            .any(|field| field.value.contains("анализ выполнен не полностью")));
    }
    #[test]
    fn report_fields_never_exceed_discord_limits() {
        let mut value = response();
        value.findings = (0..100)
            .map(|index| Finding::legacy(format!("R{index}"), "x", Severity::Low, "x".repeat(200)))
            .collect();
        for embed in format_report(&value, &context()) {
            assert!(embed.fields.len() <= MAX_EMBED_FIELDS);
            assert!(embed
                .fields
                .iter()
                .all(|field| field.value.len() <= MAX_FIELD_CHARS));
            assert!(
                embed
                    .fields
                    .iter()
                    .map(|field| field.name.len() + field.value.len())
                    .sum::<usize>()
                    + embed.title.len()
                    <= MAX_EMBED_CHARS
            );
        }
    }
}
