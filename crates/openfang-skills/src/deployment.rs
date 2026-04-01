//! Skill deployment modes — Full, Selective, and On-Demand.
//!
//! Controls how skills are loaded into an agent's context:
//! - **Full**: All assigned skills loaded at startup (default, ≤5 skills).
//! - **Selective**: Only named capabilities from each skill (>5 skills).
//! - **On-Demand**: Skills resolved dynamically per task by keyword match.

use crate::{InstalledSkill, SkillManifest};
use openfang_types::agent::{SkillCapabilityFilter, SkillDeploymentMode};
use std::collections::HashSet;
use tracing::debug;

/// Result of on-demand skill resolution for a single message.
#[derive(Debug, Clone)]
pub struct ResolvedSkills {
    /// Skills that matched the message, ordered by relevance score.
    pub matched: Vec<ResolvedSkill>,
}

/// A single skill matched during on-demand resolution.
#[derive(Debug, Clone)]
pub struct ResolvedSkill {
    /// Skill name.
    pub name: String,
    /// Match score (0.0–1.0).
    pub score: f32,
}

/// Resolves which skills (and which parts) to inject based on deployment mode.
pub struct SkillDeployer;

impl SkillDeployer {
    /// Build a skill summary string respecting the deployment mode.
    ///
    /// For Full mode: lists all allowed skills with descriptions and tools.
    /// For Selective mode: lists only skills with matching capability filters.
    /// For OnDemand mode: returns a compact "skills available on request" note
    ///   with skill names only (no prompt_context injected).
    pub fn build_summary(
        mode: &SkillDeploymentMode,
        skills: &[&InstalledSkill],
    ) -> String {
        match mode {
            SkillDeploymentMode::Full => Self::build_full_summary(skills),

            SkillDeploymentMode::Selective { filters } => {
                Self::build_selective_summary(skills, filters)
            }

            SkillDeploymentMode::OnDemand { .. } => {
                Self::build_on_demand_summary(skills)
            }
        }
    }

    /// Collect prompt_context text respecting the deployment mode.
    ///
    /// For Full mode: all prompt_context from allowed skills (existing behavior).
    /// For Selective mode: only sections matching capability keywords.
    /// For OnDemand mode: empty (nothing injected at startup).
    pub fn collect_context(
        mode: &SkillDeploymentMode,
        skills: &[&InstalledSkill],
    ) -> Vec<(String, String, bool)> {
        // Returns Vec<(skill_name, context_text, is_bundled)>
        match mode {
            SkillDeploymentMode::Full => Self::collect_full_context(skills),

            SkillDeploymentMode::Selective { filters } => {
                Self::collect_selective_context(skills, filters)
            }

            SkillDeploymentMode::OnDemand { .. } => {
                // On-demand mode injects nothing at startup.
                vec![]
            }
        }
    }

    /// Resolve which skills to load for a given user message (on-demand mode).
    ///
    /// Performs keyword matching against skill trigger descriptions.
    /// Returns skills sorted by relevance score, capped at max_skills_per_task.
    pub fn resolve_on_demand(
        message: &str,
        skills: &[&InstalledSkill],
        max_skills: usize,
        threshold: f32,
    ) -> ResolvedSkills {
        let message_lower = message.to_lowercase();
        let message_words: HashSet<&str> = message_lower
            .split_whitespace()
            .collect();

        let mut scored: Vec<ResolvedSkill> = skills
            .iter()
            .filter_map(|skill| {
                let score = Self::keyword_match_score(
                    &message_lower,
                    &message_words,
                    &skill.manifest,
                );
                if score >= threshold {
                    Some(ResolvedSkill {
                        name: skill.manifest.skill.name.clone(),
                        score,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Sort by score descending, then cap
        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(max_skills);

        if !scored.is_empty() {
            debug!(
                matched = scored.len(),
                top = %scored[0].name,
                top_score = scored[0].score,
                "On-demand skill resolution"
            );
        }

        ResolvedSkills { matched: scored }
    }

    // ── Full mode helpers ───────────────────────────────────────────────

    fn build_full_summary(skills: &[&InstalledSkill]) -> String {
        if skills.is_empty() {
            return String::new();
        }
        let mut summary = format!(
            "\n\n--- Available Skills ({}) ---\n",
            skills.len()
        );
        for skill in skills {
            let name = &skill.manifest.skill.name;
            let desc = &skill.manifest.skill.description;
            let tools: Vec<&str> = skill
                .manifest
                .tools
                .provided
                .iter()
                .map(|t| t.name.as_str())
                .collect();
            if tools.is_empty() {
                summary.push_str(&format!("- {name}: {desc}\n"));
            } else {
                summary.push_str(&format!(
                    "- {name}: {desc} [tools: {}]\n",
                    tools.join(", ")
                ));
            }
        }
        summary.push_str(
            "Use these skill tools when they match the user's request.",
        );
        summary
    }

    fn collect_full_context(
        skills: &[&InstalledSkill],
    ) -> Vec<(String, String, bool)> {
        skills
            .iter()
            .filter_map(|skill| {
                skill.manifest.prompt_context.as_ref().and_then(|ctx| {
                    if ctx.is_empty() {
                        None
                    } else {
                        let is_bundled = matches!(
                            skill.manifest.source,
                            Some(crate::SkillSource::Bundled)
                        );
                        Some((
                            skill.manifest.skill.name.clone(),
                            ctx.clone(),
                            is_bundled,
                        ))
                    }
                })
            })
            .collect()
    }

    // ── Selective mode helpers ──────────────────────────────────────────

    fn build_selective_summary(
        skills: &[&InstalledSkill],
        filters: &[SkillCapabilityFilter],
    ) -> String {
        // Only include skills that have a matching filter entry
        let filter_names: HashSet<&str> =
            filters.iter().map(|f| f.skill.as_str()).collect();

        let matched: Vec<&&InstalledSkill> = skills
            .iter()
            .filter(|s| filter_names.contains(s.manifest.skill.name.as_str()))
            .collect();

        if matched.is_empty() {
            return String::new();
        }

        let mut summary = format!(
            "\n\n--- Available Skills ({}, selective) ---\n",
            matched.len()
        );
        for skill in &matched {
            let name = &skill.manifest.skill.name;
            let filter = filters.iter().find(|f| f.skill == *name);
            let caps = filter
                .map(|f| f.capabilities.clone())
                .unwrap_or_default();

            let desc = &skill.manifest.skill.description;
            if caps.is_empty() {
                summary.push_str(&format!("- {name}: {desc} [full]\n"));
            } else {
                summary.push_str(&format!(
                    "- {name}: {desc} [capabilities: {}]\n",
                    caps.join(", ")
                ));
            }
        }
        summary.push_str(
            "Skills loaded in selective mode — only matched capabilities are active.",
        );
        summary
    }

    fn collect_selective_context(
        skills: &[&InstalledSkill],
        filters: &[SkillCapabilityFilter],
    ) -> Vec<(String, String, bool)> {
        let mut results = Vec::new();

        for skill in skills {
            let name = &skill.manifest.skill.name;
            let filter = match filters.iter().find(|f| &f.skill == name) {
                Some(f) => f,
                None => continue, // Skill not in selective filter → skip
            };

            let ctx = match skill.manifest.prompt_context.as_ref() {
                Some(c) if !c.is_empty() => c,
                _ => continue,
            };

            let is_bundled = matches!(
                skill.manifest.source,
                Some(crate::SkillSource::Bundled)
            );

            if filter.capabilities.is_empty() {
                // Empty capabilities = include everything (full for this skill)
                results.push((name.clone(), ctx.clone(), is_bundled));
            } else {
                // Filter: only include sections that mention capability keywords.
                // Split on markdown headers (## or ---) and include matching sections.
                let filtered = Self::filter_context_by_keywords(
                    ctx,
                    &filter.capabilities,
                );
                if !filtered.is_empty() {
                    results.push((name.clone(), filtered, is_bundled));
                }
            }
        }

        results
    }

    /// Filter prompt_context text to only include sections matching keywords.
    ///
    /// Splits on markdown `## ` headers. A section is included if any keyword
    /// appears (case-insensitive) in either the header or the section body.
    fn filter_context_by_keywords(
        context: &str,
        keywords: &[String],
    ) -> String {
        let keywords_lower: Vec<String> =
            keywords.iter().map(|k| k.to_lowercase()).collect();

        let mut sections = Vec::new();
        let mut current_section = String::new();

        for line in context.lines() {
            if line.starts_with("## ") && !current_section.is_empty() {
                sections.push(std::mem::take(&mut current_section));
            }
            current_section.push_str(line);
            current_section.push('\n');
        }
        if !current_section.is_empty() {
            sections.push(current_section);
        }

        let matched: Vec<&String> = sections
            .iter()
            .filter(|section| {
                let section_lower = section.to_lowercase();
                keywords_lower
                    .iter()
                    .any(|kw| section_lower.contains(kw.as_str()))
            })
            .collect();

        matched
            .into_iter()
            .cloned()
            .collect::<Vec<String>>()
            .join("\n")
    }

    // ── On-demand mode helpers ─────────────────────────────────────────

    fn build_on_demand_summary(skills: &[&InstalledSkill]) -> String {
        if skills.is_empty() {
            return String::new();
        }
        let names: Vec<&str> = skills
            .iter()
            .map(|s| s.manifest.skill.name.as_str())
            .collect();

        format!(
            "\n\n--- Skills Available On-Demand ({}) ---\n\
             The following skills can be loaded when relevant to your task: {}.\n\
             Skills are activated automatically based on the user's request.",
            names.len(),
            names.join(", ")
        )
    }

    // ── Keyword matching ───────────────────────────────────────────────

    /// Score how well a user message matches a skill's trigger surface.
    ///
    /// Checks against: skill name, description, tags, and tool names.
    /// Returns 0.0–1.0 where 1.0 = perfect match.
    fn keyword_match_score(
        message_lower: &str,
        message_words: &HashSet<&str>,
        manifest: &SkillManifest,
    ) -> f32 {
        let mut score: f32 = 0.0;
        let mut max_possible: f32 = 0.0;

        // Check skill name (weight: 3.0)
        max_possible += 3.0;
        let name_lower = manifest.skill.name.to_lowercase();
        // Split skill name on hyphens for multi-word matching
        let name_parts: Vec<&str> = name_lower.split('-').collect();
        let name_matches = name_parts
            .iter()
            .filter(|part| {
                part.len() > 2 && message_lower.contains(*part)
            })
            .count();
        if name_matches > 0 {
            score += 3.0 * (name_matches as f32 / name_parts.len() as f32);
        }

        // Check description words (weight: 2.0)
        max_possible += 2.0;
        let desc_lower = manifest.skill.description.to_lowercase();
        let desc_words: Vec<&str> = desc_lower
            .split_whitespace()
            .filter(|w| w.len() > 3) // Skip short words
            .collect();
        if !desc_words.is_empty() {
            let desc_matches = desc_words
                .iter()
                .filter(|w| message_words.contains(*w))
                .count();
            score += 2.0
                * (desc_matches as f32 / desc_words.len().min(10) as f32);
        }

        // Check tags (weight: 2.0)
        max_possible += 2.0;
        if !manifest.skill.tags.is_empty() {
            let tag_matches = manifest
                .skill
                .tags
                .iter()
                .filter(|tag| {
                    message_lower.contains(&tag.to_lowercase())
                })
                .count();
            score += 2.0
                * (tag_matches as f32
                    / manifest.skill.tags.len() as f32);
        }

        // Check tool names (weight: 3.0 — strong signal)
        max_possible += 3.0;
        if !manifest.tools.provided.is_empty() {
            let tool_matches = manifest
                .tools
                .provided
                .iter()
                .filter(|t| {
                    let tool_lower = t.name.to_lowercase();
                    let tool_parts: Vec<&str> =
                        tool_lower.split('_').collect();
                    tool_parts.iter().any(|part| {
                        part.len() > 2 && message_lower.contains(part)
                    })
                })
                .count();
            score += 3.0
                * (tool_matches as f32
                    / manifest.tools.provided.len() as f32);
        }

        if max_possible > 0.0 {
            score / max_possible
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InstalledSkill, SkillManifest, SkillMeta, SkillRequirements,
        SkillRuntime, SkillRuntimeConfig, SkillSource, SkillToolDef,
        SkillTools,
    };
    use openfang_types::agent::{SkillCapabilityFilter, SkillDeploymentMode};
    use std::path::PathBuf;

    fn make_skill(
        name: &str,
        desc: &str,
        tags: Vec<&str>,
        tools: Vec<&str>,
        prompt_ctx: Option<&str>,
    ) -> InstalledSkill {
        InstalledSkill {
            manifest: SkillManifest {
                skill: SkillMeta {
                    name: name.to_string(),
                    version: "0.1.0".to_string(),
                    description: desc.to_string(),
                    author: String::new(),
                    license: String::new(),
                    tags: tags.into_iter().map(String::from).collect(),
                },
                runtime: SkillRuntimeConfig {
                    runtime_type: SkillRuntime::PromptOnly,
                    entry: String::new(),
                },
                tools: SkillTools {
                    provided: tools
                        .into_iter()
                        .map(|t| SkillToolDef {
                            name: t.to_string(),
                            description: format!("{t} tool"),
                            input_schema: serde_json::json!({}),
                        })
                        .collect(),
                },
                requirements: SkillRequirements::default(),
                prompt_context: prompt_ctx.map(String::from),
                source: Some(SkillSource::Bundled),
            },
            path: PathBuf::from("<test>"),
            enabled: true,
        }
    }

    #[test]
    fn test_deployment_mode_serde_full() {
        let mode = SkillDeploymentMode::Full;
        let json = serde_json::to_string(&mode).unwrap();
        let back: SkillDeploymentMode =
            serde_json::from_str(&json).unwrap();
        assert_eq!(back, SkillDeploymentMode::Full);
    }

    #[test]
    fn test_deployment_mode_serde_selective() {
        let mode = SkillDeploymentMode::Selective {
            filters: vec![SkillCapabilityFilter {
                skill: "security-audit".to_string(),
                capabilities: vec![
                    "HIPAA".to_string(),
                    "encryption".to_string(),
                ],
            }],
        };
        let json = serde_json::to_string(&mode).unwrap();
        let back: SkillDeploymentMode =
            serde_json::from_str(&json).unwrap();
        assert_eq!(back, mode);
    }

    #[test]
    fn test_deployment_mode_serde_on_demand() {
        let mode = SkillDeploymentMode::OnDemand {
            max_skills_per_task: 5,
            match_threshold: 0.25,
        };
        let json = serde_json::to_string(&mode).unwrap();
        let back: SkillDeploymentMode =
            serde_json::from_str(&json).unwrap();
        assert_eq!(back, mode);
    }

    #[test]
    fn test_full_summary_lists_all() {
        let s1 = make_skill("git-expert", "Git help", vec![], vec![], None);
        let s2 = make_skill(
            "docker",
            "Docker help",
            vec![],
            vec!["docker_build"],
            None,
        );
        let skills: Vec<&InstalledSkill> = vec![&s1, &s2];
        let summary = SkillDeployer::build_summary(
            &SkillDeploymentMode::Full,
            &skills,
        );
        assert!(summary.contains("git-expert"));
        assert!(summary.contains("docker"));
        assert!(summary.contains("docker_build"));
    }

    #[test]
    fn test_selective_summary_filters() {
        let s1 = make_skill(
            "security-audit",
            "Security auditing",
            vec![],
            vec![],
            None,
        );
        let s2 = make_skill("docker", "Docker help", vec![], vec![], None);
        let skills: Vec<&InstalledSkill> = vec![&s1, &s2];

        let mode = SkillDeploymentMode::Selective {
            filters: vec![SkillCapabilityFilter {
                skill: "security-audit".to_string(),
                capabilities: vec![],
            }],
        };
        let summary = SkillDeployer::build_summary(&mode, &skills);
        assert!(summary.contains("security-audit"));
        assert!(!summary.contains("docker"));
    }

    #[test]
    fn test_on_demand_summary_compact() {
        let s1 = make_skill("git-expert", "Git help", vec![], vec![], None);
        let s2 = make_skill("docker", "Docker help", vec![], vec![], None);
        let skills: Vec<&InstalledSkill> = vec![&s1, &s2];

        let mode = SkillDeploymentMode::OnDemand {
            max_skills_per_task: 3,
            match_threshold: 0.3,
        };
        let summary = SkillDeployer::build_summary(&mode, &skills);
        assert!(summary.contains("On-Demand"));
        assert!(summary.contains("git-expert"));
        assert!(summary.contains("docker"));
        // Should NOT contain full descriptions
        assert!(!summary.contains("[tools:"));
    }

    #[test]
    fn test_on_demand_resolution_matches() {
        let s1 = make_skill(
            "kubernetes",
            "Kubernetes cluster management and debugging",
            vec!["k8s", "container", "orchestration"],
            vec!["kubectl_apply", "helm_install"],
            None,
        );
        let s2 = make_skill(
            "git-expert",
            "Git version control tips and tricks",
            vec!["git", "version-control"],
            vec!["git_log"],
            None,
        );
        let skills: Vec<&InstalledSkill> = vec![&s1, &s2];

        let result = SkillDeployer::resolve_on_demand(
            "My kubernetes pod keeps crashing, help me debug the cluster",
            &skills,
            3,
            0.1,
        );

        assert!(!result.matched.is_empty());
        assert_eq!(result.matched[0].name, "kubernetes");
    }

    #[test]
    fn test_on_demand_resolution_no_match() {
        let s1 = make_skill(
            "kubernetes",
            "Kubernetes cluster management",
            vec!["k8s"],
            vec![],
            None,
        );
        let skills: Vec<&InstalledSkill> = vec![&s1];

        let result = SkillDeployer::resolve_on_demand(
            "Help me write a poem about flowers",
            &skills,
            3,
            0.3,
        );

        assert!(result.matched.is_empty());
    }

    #[test]
    fn test_selective_context_filters_sections() {
        let ctx = "## Security Overview\nGeneral security info.\n\n\
                    ## HIPAA Compliance\nHIPAA-specific guidance.\n\n\
                    ## SOC 2 Controls\nSOC 2 details here.";
        let s1 = make_skill(
            "compliance",
            "Compliance auditing",
            vec![],
            vec![],
            Some(ctx),
        );
        let skills: Vec<&InstalledSkill> = vec![&s1];

        let filters = vec![SkillCapabilityFilter {
            skill: "compliance".to_string(),
            capabilities: vec!["HIPAA".to_string()],
        }];
        let mode = SkillDeploymentMode::Selective { filters };
        let result = SkillDeployer::collect_context(&mode, &skills);

        assert_eq!(result.len(), 1);
        let (_, text, _) = &result[0];
        assert!(text.contains("HIPAA"));
        assert!(!text.contains("SOC 2"));
    }

    #[test]
    fn test_full_context_includes_all() {
        let s1 = make_skill(
            "git-expert",
            "Git help",
            vec![],
            vec![],
            Some("Git tips and tricks"),
        );
        let s2 = make_skill(
            "docker",
            "Docker help",
            vec![],
            vec![],
            Some("Docker best practices"),
        );
        let skills: Vec<&InstalledSkill> = vec![&s1, &s2];

        let result = SkillDeployer::collect_context(
            &SkillDeploymentMode::Full,
            &skills,
        );
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_on_demand_context_empty_at_startup() {
        let s1 = make_skill(
            "git-expert",
            "Git help",
            vec![],
            vec![],
            Some("Git tips"),
        );
        let skills: Vec<&InstalledSkill> = vec![&s1];

        let mode = SkillDeploymentMode::OnDemand {
            max_skills_per_task: 3,
            match_threshold: 0.3,
        };
        let result = SkillDeployer::collect_context(&mode, &skills);
        assert!(result.is_empty());
    }

    #[test]
    fn test_on_demand_caps_results() {
        let skills_data: Vec<InstalledSkill> = (0..10)
            .map(|i| {
                make_skill(
                    &format!("skill-{i}"),
                    &format!("debug kubernetes cluster issue {i}"),
                    vec!["kubernetes"],
                    vec![],
                    None,
                )
            })
            .collect();
        let skills: Vec<&InstalledSkill> = skills_data.iter().collect();

        let result = SkillDeployer::resolve_on_demand(
            "kubernetes cluster debugging",
            &skills,
            3,
            0.05,
        );

        assert!(result.matched.len() <= 3);
    }

    #[test]
    fn test_filter_context_by_keywords() {
        let ctx = "## Authentication\nOAuth2 flows.\n\n\
                    ## Encryption\nAES-256 details.\n\n\
                    ## Logging\nAudit trail setup.";
        let result = SkillDeployer::filter_context_by_keywords(
            ctx,
            &["encryption".to_string()],
        );
        assert!(result.contains("AES-256"));
        assert!(!result.contains("OAuth2"));
        assert!(!result.contains("Audit trail"));
    }

    #[test]
    fn test_deployment_mode_default_is_full() {
        let mode = SkillDeploymentMode::default();
        assert_eq!(mode, SkillDeploymentMode::Full);
    }
}
