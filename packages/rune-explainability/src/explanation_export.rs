// ═══════════════════════════════════════════════════════════════════════
// Explanation Exporter — Trait for serializing explanations into
// structured formats for downstream consumers.
//
// Five implementations cover common regulatory and interoperability
// needs:
//   - JSON (general-purpose structured exchange)
//   - GDPR Article 22 (right to explanation in automated decisions)
//   - ECOA Adverse Action (US fair lending adverse action notices)
//   - W3C PROV Predicate (provenance-oriented explanation linking)
//   - Markdown (human-readable reports)
//
// All exported formats include confidence_score and generator_id to
// support traceability back to the explainer that produced the result.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::ExplainabilityError;

// ── ExportableExplanation ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportableExplanation {
    pub explanation_id: String,
    pub subject_id: String,
    pub explanation_type: String,
    pub summary: String,
    pub factors: Vec<ExportableFactor>,
    pub confidence_score: String,
    pub generator_id: String,
    pub generated_at: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportableFactor {
    pub factor_name: String,
    pub factor_value: String,
    pub contribution: String,
    pub direction: String,
}

// ── SubjectContext ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectContext {
    pub subject_name: Option<String>,
    pub subject_type: String,
    pub locale: Option<String>,
    pub additional: HashMap<String, String>,
}

impl SubjectContext {
    pub fn new(subject_type: &str) -> Self {
        Self {
            subject_name: None,
            subject_type: subject_type.to_string(),
            locale: None,
            additional: HashMap::new(),
        }
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.subject_name = Some(name.to_string());
        self
    }

    pub fn with_locale(mut self, locale: &str) -> Self {
        self.locale = Some(locale.to_string());
        self
    }
}

// ── ExplanationExporter trait ──────────────────────────────────

pub trait ExplanationExporter {
    fn export_explanation(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<Vec<u8>, ExplainabilityError>;

    fn export_batch(
        &self,
        explanations: &[ExportableExplanation],
    ) -> Result<Vec<u8>, ExplainabilityError>;

    fn export_explanation_with_subject_context(
        &self,
        explanation: &ExportableExplanation,
        context: &SubjectContext,
    ) -> Result<Vec<u8>, ExplainabilityError>;

    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonExplanationExporter ────────────────────────────────────

pub struct JsonExplanationExporter;

impl Default for JsonExplanationExporter {
    fn default() -> Self { Self }
}

impl JsonExplanationExporter {
    pub fn new() -> Self { Self }

    fn explanation_to_json(explanation: &ExportableExplanation) -> serde_json::Value {
        let factors: Vec<serde_json::Value> = explanation.factors.iter().map(|f| {
            serde_json::json!({
                "factor_name": f.factor_name,
                "factor_value": f.factor_value,
                "contribution": f.contribution,
                "direction": f.direction,
            })
        }).collect();

        serde_json::json!({
            "explanation_id": explanation.explanation_id,
            "subject_id": explanation.subject_id,
            "explanation_type": explanation.explanation_type,
            "summary": explanation.summary,
            "factors": factors,
            "confidence_score": explanation.confidence_score,
            "generator_id": explanation.generator_id,
            "generated_at": explanation.generated_at,
            "metadata": explanation.metadata,
        })
    }
}

impl ExplanationExporter for JsonExplanationExporter {
    fn export_explanation(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let json = Self::explanation_to_json(explanation);
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        explanations: &[ExportableExplanation],
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let arr: Vec<serde_json::Value> = explanations.iter()
            .map(Self::explanation_to_json)
            .collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn export_explanation_with_subject_context(
        &self,
        explanation: &ExportableExplanation,
        context: &SubjectContext,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let mut json = Self::explanation_to_json(explanation);
        let obj = json.as_object_mut().unwrap();
        let mut ctx = serde_json::Map::new();
        if let Some(name) = &context.subject_name {
            ctx.insert("subject_name".into(), serde_json::Value::String(name.clone()));
        }
        ctx.insert("subject_type".into(), serde_json::Value::String(context.subject_type.clone()));
        if let Some(locale) = &context.locale {
            ctx.insert("locale".into(), serde_json::Value::String(locale.clone()));
        }
        obj.insert("subject_context".into(), serde_json::Value::Object(ctx));
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str { "json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── GdprArticle22Exporter ──────────────────────────────────────

pub struct GdprArticle22Exporter;

impl Default for GdprArticle22Exporter {
    fn default() -> Self { Self }
}

impl GdprArticle22Exporter {
    pub fn new() -> Self { Self }
}

impl ExplanationExporter for GdprArticle22Exporter {
    fn export_explanation(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let factors: Vec<serde_json::Value> = explanation.factors.iter().map(|f| {
            serde_json::json!({
                "factor": f.factor_name,
                "influence": f.contribution,
                "direction": f.direction,
            })
        }).collect();

        let json = serde_json::json!({
            "gdpr_article_22": {
                "decision_id": explanation.explanation_id,
                "subject_id": explanation.subject_id,
                "automated_decision_summary": explanation.summary,
                "significant_factors": factors,
                "logic_involved": explanation.explanation_type,
                "confidence_score": explanation.confidence_score,
                "generator_id": explanation.generator_id,
                "right_to_contest": true,
                "right_to_human_review": true,
                "generated_at": explanation.generated_at,
            }
        });
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        explanations: &[ExportableExplanation],
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let mut results = Vec::new();
        for exp in explanations {
            let exported = self.export_explanation(exp)?;
            results.extend_from_slice(&exported);
            results.push(b'\n');
        }
        Ok(results)
    }

    fn export_explanation_with_subject_context(
        &self,
        explanation: &ExportableExplanation,
        context: &SubjectContext,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let factors: Vec<serde_json::Value> = explanation.factors.iter().map(|f| {
            serde_json::json!({
                "factor": f.factor_name,
                "influence": f.contribution,
                "direction": f.direction,
            })
        }).collect();

        let mut data_subject = serde_json::Map::new();
        if let Some(name) = &context.subject_name {
            data_subject.insert("name".into(), serde_json::Value::String(name.clone()));
        }
        data_subject.insert("type".into(), serde_json::Value::String(context.subject_type.clone()));
        if let Some(locale) = &context.locale {
            data_subject.insert("locale".into(), serde_json::Value::String(locale.clone()));
        }

        let json = serde_json::json!({
            "gdpr_article_22": {
                "decision_id": explanation.explanation_id,
                "data_subject": data_subject,
                "automated_decision_summary": explanation.summary,
                "significant_factors": factors,
                "logic_involved": explanation.explanation_type,
                "confidence_score": explanation.confidence_score,
                "generator_id": explanation.generator_id,
                "right_to_contest": true,
                "right_to_human_review": true,
                "generated_at": explanation.generated_at,
            }
        });
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str { "gdpr-article-22" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── EcoaAdverseActionExporter ──────────────────────────────────

pub struct EcoaAdverseActionExporter;

impl Default for EcoaAdverseActionExporter {
    fn default() -> Self { Self }
}

impl EcoaAdverseActionExporter {
    pub fn new() -> Self { Self }
}

impl ExplanationExporter for EcoaAdverseActionExporter {
    fn export_explanation(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let reasons: Vec<serde_json::Value> = explanation.factors.iter()
            .take(4)
            .enumerate()
            .map(|(i, f)| {
                serde_json::json!({
                    "reason_code": format!("R{}", i + 1),
                    "factor": f.factor_name,
                    "description": format!("{} (contribution: {}, direction: {})", f.factor_name, f.contribution, f.direction),
                })
            })
            .collect();

        let json = serde_json::json!({
            "ecoa_adverse_action": {
                "notice_id": explanation.explanation_id,
                "applicant_id": explanation.subject_id,
                "action_taken": explanation.summary,
                "principal_reasons": reasons,
                "credit_score_used": explanation.metadata.get("credit_score").cloned(),
                "confidence_score": explanation.confidence_score,
                "generator_id": explanation.generator_id,
                "generated_at": explanation.generated_at,
            }
        });
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        explanations: &[ExportableExplanation],
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let mut results = Vec::new();
        for exp in explanations {
            let exported = self.export_explanation(exp)?;
            results.extend_from_slice(&exported);
            results.push(b'\n');
        }
        Ok(results)
    }

    fn export_explanation_with_subject_context(
        &self,
        explanation: &ExportableExplanation,
        context: &SubjectContext,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let reasons: Vec<serde_json::Value> = explanation.factors.iter()
            .take(4)
            .enumerate()
            .map(|(i, f)| {
                serde_json::json!({
                    "reason_code": format!("R{}", i + 1),
                    "factor": f.factor_name,
                    "description": format!("{} (contribution: {}, direction: {})", f.factor_name, f.contribution, f.direction),
                })
            })
            .collect();

        let mut applicant = serde_json::Map::new();
        applicant.insert("id".into(), serde_json::Value::String(explanation.subject_id.clone()));
        if let Some(name) = &context.subject_name {
            applicant.insert("name".into(), serde_json::Value::String(name.clone()));
        }

        let json = serde_json::json!({
            "ecoa_adverse_action": {
                "notice_id": explanation.explanation_id,
                "applicant": applicant,
                "action_taken": explanation.summary,
                "principal_reasons": reasons,
                "credit_score_used": explanation.metadata.get("credit_score").cloned(),
                "confidence_score": explanation.confidence_score,
                "generator_id": explanation.generator_id,
                "generated_at": explanation.generated_at,
            }
        });
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str { "ecoa-adverse-action" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── W3cProvPredicateExporter ───────────────────────────────────

pub struct W3cProvPredicateExporter;

impl Default for W3cProvPredicateExporter {
    fn default() -> Self { Self }
}

impl W3cProvPredicateExporter {
    pub fn new() -> Self { Self }
}

impl ExplanationExporter for W3cProvPredicateExporter {
    fn export_explanation(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let influences: Vec<serde_json::Value> = explanation.factors.iter().map(|f| {
            serde_json::json!({
                "prov:entity": f.factor_name,
                "prov:value": f.factor_value,
                "prov:influence": f.contribution,
            })
        }).collect();

        let json = serde_json::json!({
            "@context": {
                "prov": "http://www.w3.org/ns/prov#",
                "rune": "urn:rune:explainability:"
            },
            "@type": "prov:Activity",
            "prov:qualifiedInfluence": influences,
            "rune:explanation_id": explanation.explanation_id,
            "rune:subject_id": explanation.subject_id,
            "rune:explanation_type": explanation.explanation_type,
            "rune:summary": explanation.summary,
            "rune:confidence_score": explanation.confidence_score,
            "rune:generator_id": explanation.generator_id,
            "prov:generatedAtTime": explanation.generated_at,
        });
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        explanations: &[ExportableExplanation],
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let arr: Vec<serde_json::Value> = explanations.iter()
            .map(|exp| {
                let influences: Vec<serde_json::Value> = exp.factors.iter().map(|f| {
                    serde_json::json!({
                        "prov:entity": f.factor_name,
                        "prov:value": f.factor_value,
                        "prov:influence": f.contribution,
                    })
                }).collect();
                serde_json::json!({
                    "@type": "prov:Activity",
                    "prov:qualifiedInfluence": influences,
                    "rune:explanation_id": exp.explanation_id,
                    "rune:subject_id": exp.subject_id,
                    "rune:confidence_score": exp.confidence_score,
                    "rune:generator_id": exp.generator_id,
                })
            })
            .collect();
        let json = serde_json::json!({
            "@context": {
                "prov": "http://www.w3.org/ns/prov#",
                "rune": "urn:rune:explainability:"
            },
            "@graph": arr,
        });
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn export_explanation_with_subject_context(
        &self,
        explanation: &ExportableExplanation,
        context: &SubjectContext,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let influences: Vec<serde_json::Value> = explanation.factors.iter().map(|f| {
            serde_json::json!({
                "prov:entity": f.factor_name,
                "prov:value": f.factor_value,
                "prov:influence": f.contribution,
            })
        }).collect();

        let mut json = serde_json::json!({
            "@context": {
                "prov": "http://www.w3.org/ns/prov#",
                "rune": "urn:rune:explainability:"
            },
            "@type": "prov:Activity",
            "prov:qualifiedInfluence": influences,
            "rune:explanation_id": explanation.explanation_id,
            "rune:subject_id": explanation.subject_id,
            "rune:explanation_type": explanation.explanation_type,
            "rune:summary": explanation.summary,
            "rune:confidence_score": explanation.confidence_score,
            "rune:generator_id": explanation.generator_id,
            "prov:generatedAtTime": explanation.generated_at,
        });
        let obj = json.as_object_mut().unwrap();
        let mut agent = serde_json::Map::new();
        agent.insert("@type".into(), serde_json::Value::String("prov:Agent".into()));
        agent.insert("rune:subject_type".into(), serde_json::Value::String(context.subject_type.clone()));
        if let Some(name) = &context.subject_name {
            agent.insert("prov:label".into(), serde_json::Value::String(name.clone()));
        }
        obj.insert("prov:wasAssociatedWith".into(), serde_json::Value::Object(agent));
        serde_json::to_vec_pretty(&json)
            .map_err(|e| ExplainabilityError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str { "w3c-prov-predicate" }
    fn content_type(&self) -> &str { "application/ld+json" }
}

// ── MarkdownExplanationExporter ────────────────────────────────

pub struct MarkdownExplanationExporter;

impl Default for MarkdownExplanationExporter {
    fn default() -> Self { Self }
}

impl MarkdownExplanationExporter {
    pub fn new() -> Self { Self }

    fn render(explanation: &ExportableExplanation, context: Option<&SubjectContext>) -> Vec<u8> {
        let mut md = String::new();
        md.push_str(&format!("# Explanation: {}\n\n", explanation.explanation_id));

        if let Some(ctx) = context {
            if let Some(name) = &ctx.subject_name {
                md.push_str(&format!("**Subject**: {} ({})\n\n", name, ctx.subject_type));
            } else {
                md.push_str(&format!("**Subject**: {} ({})\n\n", explanation.subject_id, ctx.subject_type));
            }
        } else {
            md.push_str(&format!("**Subject**: {}\n\n", explanation.subject_id));
        }

        md.push_str(&format!("**Type**: {}\n\n", explanation.explanation_type));
        md.push_str(&format!("**Summary**: {}\n\n", explanation.summary));
        md.push_str(&format!("**Confidence**: {}\n\n", explanation.confidence_score));
        md.push_str(&format!("**Generator**: {}\n\n", explanation.generator_id));

        if !explanation.factors.is_empty() {
            md.push_str("## Contributing Factors\n\n");
            md.push_str("| Factor | Value | Contribution | Direction |\n");
            md.push_str("|--------|-------|--------------|-----------|\n");
            for f in &explanation.factors {
                md.push_str(&format!("| {} | {} | {} | {} |\n",
                    f.factor_name, f.factor_value, f.contribution, f.direction));
            }
            md.push('\n');
        }

        md.into_bytes()
    }
}

impl ExplanationExporter for MarkdownExplanationExporter {
    fn export_explanation(
        &self,
        explanation: &ExportableExplanation,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        Ok(Self::render(explanation, None))
    }

    fn export_batch(
        &self,
        explanations: &[ExportableExplanation],
    ) -> Result<Vec<u8>, ExplainabilityError> {
        let mut result = Vec::new();
        for exp in explanations {
            result.extend_from_slice(&Self::render(exp, None));
            result.extend_from_slice(b"---\n\n");
        }
        Ok(result)
    }

    fn export_explanation_with_subject_context(
        &self,
        explanation: &ExportableExplanation,
        context: &SubjectContext,
    ) -> Result<Vec<u8>, ExplainabilityError> {
        Ok(Self::render(explanation, Some(context)))
    }

    fn format_name(&self) -> &str { "markdown" }
    fn content_type(&self) -> &str { "text/markdown" }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_explanation() -> ExportableExplanation {
        ExportableExplanation {
            explanation_id: "exp-1".to_string(),
            subject_id: "pred-1".to_string(),
            explanation_type: "feature-attribution".to_string(),
            summary: "Loan denied due to low income".to_string(),
            factors: vec![
                ExportableFactor {
                    factor_name: "income".to_string(),
                    factor_value: "30000".to_string(),
                    contribution: "0.7".to_string(),
                    direction: "negative".to_string(),
                },
                ExportableFactor {
                    factor_name: "credit_score".to_string(),
                    factor_value: "650".to_string(),
                    contribution: "0.2".to_string(),
                    direction: "negative".to_string(),
                },
            ],
            confidence_score: "0.85".to_string(),
            generator_id: "lc-explainer-1".to_string(),
            generated_at: 1000,
            metadata: HashMap::from([("credit_score".into(), "650".into())]),
        }
    }

    #[test]
    fn test_json_exporter() {
        let exporter = JsonExplanationExporter::new();
        let exp = sample_explanation();
        let result = exporter.export_explanation(&exp).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("exp-1"));
        assert!(text.contains("income"));
        assert_eq!(exporter.format_name(), "json");
        assert_eq!(exporter.content_type(), "application/json");
    }

    #[test]
    fn test_json_batch() {
        let exporter = JsonExplanationExporter::new();
        let exp = sample_explanation();
        let result = exporter.export_batch(&[exp.clone(), exp]).unwrap();
        let arr: Vec<serde_json::Value> = serde_json::from_slice(&result).unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_json_with_context() {
        let exporter = JsonExplanationExporter::new();
        let exp = sample_explanation();
        let ctx = SubjectContext::new("applicant").with_name("Jane Doe").with_locale("en-US");
        let result = exporter.export_explanation_with_subject_context(&exp, &ctx).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("Jane Doe"));
        assert!(text.contains("applicant"));
    }

    #[test]
    fn test_gdpr_exporter() {
        let exporter = GdprArticle22Exporter::new();
        let exp = sample_explanation();
        let result = exporter.export_explanation(&exp).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("gdpr_article_22"));
        assert!(text.contains("right_to_contest"));
        assert!(text.contains("right_to_human_review"));
        assert_eq!(exporter.format_name(), "gdpr-article-22");
    }

    #[test]
    fn test_gdpr_with_context() {
        let exporter = GdprArticle22Exporter::new();
        let exp = sample_explanation();
        let ctx = SubjectContext::new("data_subject").with_name("John Smith");
        let result = exporter.export_explanation_with_subject_context(&exp, &ctx).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("data_subject"));
        assert!(text.contains("John Smith"));
    }

    #[test]
    fn test_ecoa_exporter() {
        let exporter = EcoaAdverseActionExporter::new();
        let exp = sample_explanation();
        let result = exporter.export_explanation(&exp).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("ecoa_adverse_action"));
        assert!(text.contains("principal_reasons"));
        assert!(text.contains("R1"));
        assert_eq!(exporter.format_name(), "ecoa-adverse-action");
    }

    #[test]
    fn test_ecoa_max_four_reasons() {
        let exporter = EcoaAdverseActionExporter::new();
        let mut exp = sample_explanation();
        for i in 0..6 {
            exp.factors.push(ExportableFactor {
                factor_name: format!("factor_{i}"),
                factor_value: "1".into(),
                contribution: "0.1".into(),
                direction: "negative".into(),
            });
        }
        let result = exporter.export_explanation(&exp).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let reasons = parsed["ecoa_adverse_action"]["principal_reasons"].as_array().unwrap();
        assert_eq!(reasons.len(), 4);
    }

    #[test]
    fn test_w3c_prov_exporter() {
        let exporter = W3cProvPredicateExporter::new();
        let exp = sample_explanation();
        let result = exporter.export_explanation(&exp).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("prov:Activity"));
        assert!(text.contains("prov:qualifiedInfluence"));
        assert_eq!(exporter.format_name(), "w3c-prov-predicate");
        assert_eq!(exporter.content_type(), "application/ld+json");
    }

    #[test]
    fn test_w3c_prov_batch() {
        let exporter = W3cProvPredicateExporter::new();
        let exp = sample_explanation();
        let result = exporter.export_batch(&[exp]).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert!(parsed["@graph"].is_array());
    }

    #[test]
    fn test_markdown_exporter() {
        let exporter = MarkdownExplanationExporter::new();
        let exp = sample_explanation();
        let result = exporter.export_explanation(&exp).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("# Explanation: exp-1"));
        assert!(text.contains("| income |"));
        assert_eq!(exporter.format_name(), "markdown");
        assert_eq!(exporter.content_type(), "text/markdown");
    }

    #[test]
    fn test_markdown_with_context() {
        let exporter = MarkdownExplanationExporter::new();
        let exp = sample_explanation();
        let ctx = SubjectContext::new("applicant").with_name("Jane Doe");
        let result = exporter.export_explanation_with_subject_context(&exp, &ctx).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("Jane Doe"));
    }

    #[test]
    fn test_markdown_batch() {
        let exporter = MarkdownExplanationExporter::new();
        let exp = sample_explanation();
        let result = exporter.export_batch(&[exp.clone(), exp]).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert_eq!(text.matches("# Explanation:").count(), 2);
        assert!(text.contains("---"));
    }

    #[test]
    fn test_subject_context_builder() {
        let ctx = SubjectContext::new("applicant")
            .with_name("Jane")
            .with_locale("en-GB");
        assert_eq!(ctx.subject_name.as_deref(), Some("Jane"));
        assert_eq!(ctx.locale.as_deref(), Some("en-GB"));
        assert_eq!(ctx.subject_type, "applicant");
    }
}
