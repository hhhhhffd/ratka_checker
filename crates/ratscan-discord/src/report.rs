use ratscan_models::scan::ScanResponse;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportContext {
    pub filename: String,
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

/// Renders the compact result intended for the user-facing scan thread.
pub fn format_report(result: &ScanResponse, context: &ReportContext) -> Vec<ReportEmbed> {
    vec![ReportEmbed {
        title: "Summary".into(),
        description: String::new(),
        fields: vec![
            ReportField {
                name: "Verdict".into(),
                value: format!("`{}`", verdict(result)),
            },
            ReportField {
                name: "Risk".into(),
                value: format!("`{} / 100`", result.risk_score),
            },
            ReportField {
                name: "SHA-256".into(),
                value: format!("`{}`", result.sha256),
            },
            ReportField {
                name: "File".into(),
                value: format!("`{}`", escape(&context.filename)),
            },
        ],
    }]
}

fn verdict(result: &ScanResponse) -> &'static str {
    result
        .verdict
        .as_ref()
        .map_or("unknown", ratscan_models::scan::Verdict::as_str)
}

fn escape(value: &str) -> String {
    value.replace('`', "'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratscan_models::scan::{
        AnalysisCoverage, Confidence, Obfuscation, ObfuscationLevel, ScanStatus, Verdict,
    };
    use uuid::Uuid;

    fn response() -> ScanResponse {
        ScanResponse {
            scan_id: Uuid::nil(),
            status: ScanStatus::Done,
            sha256: "hash".into(),
            verdict: Some(Verdict::Clean),
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

    #[test]
    fn user_report_contains_only_summary_fields() {
        let report = format_report(
            &response(),
            &ReportContext {
                filename: "a.jar".into(),
            },
        );

        assert_eq!(report.len(), 1);
        assert_eq!(report[0].title, "Summary");
        assert_eq!(
            report[0]
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Verdict", "Risk", "SHA-256", "File"]
        );
        assert!(report[0]
            .fields
            .iter()
            .all(|field| !matches!(field.name.as_str(), "Confidence" | "Coverage")));
    }
}
