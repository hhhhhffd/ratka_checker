//! Pure code-scope classification for archive layers.
//!
//! This module deliberately does not inspect ZIP entries or parse class files. Archive parsing
//! supplies the small DTOs below, then uses the classifications to decide which code is eligible
//! for correlation. Keeping that policy here prevents dependency hints from being accidentally
//! lost when nested archives are processed.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::models::scan::{CodeScope, Confidence};

/// Metadata identifying a dependency without requiring the classifier to parse Maven files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyMetadata {
    pub name: String,
    pub version: Option<String>,
    /// Namespace roots declared by dependency metadata, for example `org/example/library`.
    pub package_roots: Vec<String>,
}

/// Context attached to one archive layer by the archive parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveScopeInput {
    pub archive_id: String,
    pub archive_path: String,
    pub depth: usize,
    /// A dependency explicitly declared by the parent mod descriptor or nested-JAR metadata.
    pub declared_dependency: Option<DependencyMetadata>,
    /// A nested archive with its own mod descriptor is an independently loadable mod.
    pub has_mod_metadata: bool,
    /// Entrypoints found in this archive's Fabric/Forge/plugin metadata.
    pub entrypoint_classes: Vec<String>,
    /// Mixin package roots supplied by metadata, when available.
    pub mixin_package_roots: Vec<String>,
    /// Maven package roots supplied by `META-INF/maven` metadata, when available.
    pub maven_package_roots: Vec<String>,
}

/// A class to classify. Names can use JVM (`a/b/C`) or Java (`a.b.C`) notation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassScopeInput {
    pub archive_id: String,
    pub class_name: String,
}

/// All inputs required to classify a set of classes without side effects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScopeClassificationInput {
    pub archives: Vec<ArchiveScopeInput>,
    pub classes: Vec<ClassScopeInput>,
    /// Package roots inferred by a caller from the archive-wide class distribution.
    pub dominant_package_roots: Vec<String>,
}

/// The reason that produced the final classification. It is safe to show in diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClassificationReason {
    DirectEntrypoint,
    EntrypointPackage,
    MixinPackage,
    MavenPackage,
    DeclaredDependency,
    DependencyPackage,
    KnownNamespace,
    NestedModMetadata,
    GeneratedClass,
    DominantRootPackage,
    RootArchiveFallback,
    UnknownNestedArchive,
    MissingArchiveMetadata,
}

/// A class scope together with the attribution data needed by later data-flow policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassScopeClassification {
    pub archive_id: String,
    pub class_name: String,
    pub scope: CodeScope,
    pub dependency: Option<DependencyMetadata>,
    /// `true` only when the class is a declared entrypoint. Package affinity is not proof of reachability.
    pub reachable_from_entrypoint: bool,
    pub classification_confidence: Confidence,
    pub reason: ClassificationReason,
}

/// Classifies all supplied classes. The function is deterministic and performs no I/O.
pub fn classify_classes(input: &ScopeClassificationInput) -> Vec<ClassScopeClassification> {
    let archives = input
        .archives
        .iter()
        .map(|archive| (archive.archive_id.as_str(), archive))
        .collect::<HashMap<_, _>>();
    let dominant_roots = normalized_roots(&input.dominant_package_roots);

    input
        .classes
        .iter()
        .map(|class| {
            classify_class(
                class,
                archives.get(class.archive_id.as_str()).copied(),
                &dominant_roots,
            )
        })
        .collect()
}

fn classify_class(
    class: &ClassScopeInput,
    archive: Option<&ArchiveScopeInput>,
    dominant_roots: &BTreeSet<String>,
) -> ClassScopeClassification {
    let class_name = normalize_class_name(&class.class_name);
    let Some(archive) = archive else {
        return classification(
            class,
            CodeScope::Unknown,
            None,
            false,
            Confidence::Low,
            ClassificationReason::MissingArchiveMetadata,
        );
    };

    let entrypoints = archive
        .entrypoint_classes
        .iter()
        .map(|entrypoint| normalize_entrypoint(entrypoint))
        .collect::<HashSet<_>>();
    if let Some(dependency) = &archive.declared_dependency {
        let dependency_roots = normalized_roots(&dependency.package_roots);
        if dependency_roots.is_empty() || matches_any_root(&class_name, &dependency_roots) {
            return classification(
                class,
                CodeScope::BundledDependency,
                Some(dependency.clone()),
                false,
                Confidence::High,
                ClassificationReason::DeclaredDependency,
            );
        }
        return classification(
            class,
            CodeScope::BundledDependency,
            Some(dependency.clone()),
            false,
            Confidence::Medium,
            ClassificationReason::DependencyPackage,
        );
    }
    if archive.depth > 0 && archive.has_mod_metadata {
        return classification(
            class,
            CodeScope::NestedMod,
            None,
            entrypoints.contains(&class_name),
            Confidence::High,
            ClassificationReason::NestedModMetadata,
        );
    }
    if entrypoints.contains(&class_name) {
        return classification(
            class,
            CodeScope::FirstParty,
            None,
            true,
            Confidence::High,
            ClassificationReason::DirectEntrypoint,
        );
    }

    if is_generated_class(&class_name) {
        return classification(
            class,
            CodeScope::GeneratedCode,
            None,
            false,
            Confidence::High,
            ClassificationReason::GeneratedClass,
        );
    }

    if let Some(dependency) = known_namespace_dependency(&class_name) {
        return classification(
            class,
            CodeScope::BundledDependency,
            Some(dependency),
            false,
            Confidence::High,
            ClassificationReason::KnownNamespace,
        );
    }

    let entrypoint_roots = package_roots(&entrypoints);
    if matches_any_root(&class_name, &entrypoint_roots) {
        return classification(
            class,
            CodeScope::FirstParty,
            None,
            false,
            Confidence::High,
            ClassificationReason::EntrypointPackage,
        );
    }

    let mixin_roots = normalized_roots(&archive.mixin_package_roots);
    if matches_any_root(&class_name, &mixin_roots) {
        return classification(
            class,
            CodeScope::FirstParty,
            None,
            false,
            Confidence::Medium,
            ClassificationReason::MixinPackage,
        );
    }

    let maven_roots = normalized_roots(&archive.maven_package_roots);
    if matches_any_root(&class_name, &maven_roots) {
        return classification(
            class,
            CodeScope::BundledDependency,
            archive.declared_dependency.clone(),
            false,
            Confidence::High,
            ClassificationReason::MavenPackage,
        );
    }

    if archive.depth > 0 && archive.has_mod_metadata {
        return classification(
            class,
            CodeScope::NestedMod,
            None,
            false,
            Confidence::High,
            ClassificationReason::NestedModMetadata,
        );
    }

    if archive.depth == 0 && matches_any_root(&class_name, dominant_roots) {
        return classification(
            class,
            CodeScope::FirstParty,
            None,
            false,
            Confidence::Medium,
            ClassificationReason::DominantRootPackage,
        );
    }

    if archive.depth == 0 {
        return classification(
            class,
            CodeScope::FirstParty,
            None,
            false,
            Confidence::Low,
            ClassificationReason::RootArchiveFallback,
        );
    }

    classification(
        class,
        CodeScope::Unknown,
        None,
        false,
        Confidence::Medium,
        ClassificationReason::UnknownNestedArchive,
    )
}

fn classification(
    class: &ClassScopeInput,
    scope: CodeScope,
    dependency: Option<DependencyMetadata>,
    reachable_from_entrypoint: bool,
    classification_confidence: Confidence,
    reason: ClassificationReason,
) -> ClassScopeClassification {
    ClassScopeClassification {
        archive_id: class.archive_id.clone(),
        class_name: normalize_class_name(&class.class_name),
        scope,
        dependency,
        reachable_from_entrypoint,
        classification_confidence,
        reason,
    }
}

fn normalize_entrypoint(entrypoint: &str) -> String {
    entrypoint
        .split_once(':')
        .map_or(entrypoint, |(_, class_name)| class_name)
        .trim()
        .replace('.', "/")
        .trim_end_matches(".class")
        .to_owned()
}

fn normalize_class_name(class_name: &str) -> String {
    class_name
        .trim()
        .replace('\\', "/")
        .replace('.', "/")
        .trim_end_matches(".class")
        .to_owned()
}

fn normalized_roots(roots: &[String]) -> BTreeSet<String> {
    roots
        .iter()
        .map(|root| normalize_class_name(root).trim_end_matches('/').to_owned())
        .filter(|root| !root.is_empty())
        .collect()
}

fn package_roots(entrypoints: &HashSet<String>) -> BTreeSet<String> {
    entrypoints
        .iter()
        .filter_map(|entrypoint| entrypoint.rsplit_once('/').map(|(package, _)| package))
        .map(|package| {
            let segments = package.split('/').collect::<Vec<_>>();
            let root_length = segments.len().min(3);
            segments[..root_length].join("/")
        })
        .collect()
}

fn matches_any_root(class_name: &str, roots: &BTreeSet<String>) -> bool {
    roots
        .iter()
        .any(|root| class_name == root || class_name.starts_with(&format!("{root}/")))
}

fn is_generated_class(class_name: &str) -> bool {
    class_name.contains("$$Lambda$")
        || class_name.contains("$lambda$")
        || class_name.contains("$DefaultImpls")
        || class_name.contains("$WhenMappings")
        || class_name.ends_with("/package-info")
        || class_name.ends_with("/module-info")
}

fn known_namespace_dependency(class_name: &str) -> Option<DependencyMetadata> {
    const KNOWN_NAMESPACES: &[(&str, &str)] = &[
        ("com/google/gson/", "Gson"),
        ("com/google/common/", "Guava"),
        ("com/kenai/", "JNA"),
        ("io/netty/", "Netty"),
        ("jnr/", "JNR"),
        ("kotlin/", "Kotlin"),
        ("kotlinx/", "KotlinX"),
        ("net/fabricmc/", "Fabric API/Loader"),
        ("net/minecraft/", "Minecraft runtime"),
        ("org/apache/", "Apache library"),
        ("org/jetbrains/", "JetBrains library"),
        ("org/intellij/", "IntelliJ platform"),
        ("org/lwjgl/", "LWJGL"),
        ("org/objectweb/asm/", "ASM"),
        ("org/slf4j/", "SLF4J"),
        ("org/sqlite/", "SQLite JDBC"),
    ];

    let lower = class_name.to_ascii_lowercase();
    KNOWN_NAMESPACES.iter().find_map(|(prefix, name)| {
        lower.starts_with(prefix).then(|| DependencyMetadata {
            name: (*name).to_owned(),
            version: None,
            package_roots: vec![prefix.trim_end_matches('/').to_owned()],
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(
        id: &str,
        depth: usize,
        declared_dependency: Option<DependencyMetadata>,
        has_mod_metadata: bool,
        entrypoints: &[&str],
    ) -> ArchiveScopeInput {
        ArchiveScopeInput {
            archive_id: id.to_owned(),
            archive_path: format!("{id}.jar"),
            depth,
            declared_dependency,
            has_mod_metadata,
            entrypoint_classes: entrypoints.iter().map(ToString::to_string).collect(),
            mixin_package_roots: Vec::new(),
            maven_package_roots: Vec::new(),
        }
    }

    fn classify(input: ScopeClassificationInput) -> ClassScopeClassification {
        let mut results = classify_classes(&input);
        assert_eq!(results.len(), 1);
        results.remove(0)
    }

    #[test]
    fn direct_entrypoint_is_first_party_and_reachable() {
        let result = classify(ScopeClassificationInput {
            archives: vec![archive(
                "root",
                0,
                None,
                false,
                &["example.mod.Initializer"],
            )],
            classes: vec![ClassScopeInput {
                archive_id: "root".to_owned(),
                class_name: "example/mod/Initializer".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::FirstParty);
        assert!(result.reachable_from_entrypoint);
        assert_eq!(result.classification_confidence, Confidence::High);
        assert_eq!(result.reason, ClassificationReason::DirectEntrypoint);
    }

    #[test]
    fn entrypoint_package_is_first_party_but_not_proven_reachable() {
        let result = classify(ScopeClassificationInput {
            archives: vec![archive(
                "root",
                0,
                None,
                false,
                &["com.example.mod.Initializer"],
            )],
            classes: vec![ClassScopeInput {
                archive_id: "root".to_owned(),
                class_name: "com.example.mod.network.Client".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::FirstParty);
        assert!(!result.reachable_from_entrypoint);
        assert_eq!(result.reason, ClassificationReason::EntrypointPackage);
    }

    #[test]
    fn known_namespace_wins_over_root_archive_fallback() {
        let result = classify(ScopeClassificationInput {
            archives: vec![archive("root", 0, None, false, &[])],
            classes: vec![ClassScopeInput {
                archive_id: "root".to_owned(),
                class_name: "com/google/gson/Gson".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::BundledDependency);
        assert_eq!(result.dependency.unwrap().name, "Gson");
        assert_eq!(result.reason, ClassificationReason::KnownNamespace);
    }

    #[test]
    fn declared_nested_dependency_is_classified_with_its_metadata() {
        let dependency = DependencyMetadata {
            name: "ZIP4J".to_owned(),
            version: Some("2.11.5".to_owned()),
            package_roots: vec!["net/lingala/zip4j".to_owned()],
        };
        let result = classify(ScopeClassificationInput {
            archives: vec![archive("zip4j", 1, Some(dependency.clone()), false, &[])],
            classes: vec![ClassScopeInput {
                archive_id: "zip4j".to_owned(),
                class_name: "net/lingala/zip4j/ZipFile".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::BundledDependency);
        assert_eq!(result.dependency, Some(dependency));
        assert_eq!(result.reason, ClassificationReason::DeclaredDependency);
    }

    #[test]
    fn nested_archive_with_own_mod_metadata_is_nested_mod() {
        let result = classify(ScopeClassificationInput {
            archives: vec![archive("nested-mod", 1, None, true, &[])],
            classes: vec![ClassScopeInput {
                archive_id: "nested-mod".to_owned(),
                class_name: "example/embedded/Feature".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::NestedMod);
        assert_eq!(result.reason, ClassificationReason::NestedModMetadata);
    }

    #[test]
    fn declared_dependency_wins_over_nested_mod_metadata() {
        let dependency = DependencyMetadata {
            name: "modmenu".to_owned(),
            version: Some("17.0.0".to_owned()),
            package_roots: Vec::new(),
        };
        let result = classify(ScopeClassificationInput {
            archives: vec![archive(
                "modmenu",
                1,
                Some(dependency.clone()),
                true,
                &["com.terraformersmc.modmenu.ModMenu"],
            )],
            classes: vec![ClassScopeInput {
                archive_id: "modmenu".to_owned(),
                class_name: "com/terraformersmc/modmenu/ModMenu".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::BundledDependency);
        assert_eq!(result.dependency, Some(dependency));
        assert_eq!(result.reason, ClassificationReason::DeclaredDependency);
        assert!(!result.reachable_from_entrypoint);
    }

    #[test]
    fn maven_root_marks_dependency_even_without_explicit_coordinate() {
        let mut archive = archive("nested", 1, None, false, &[]);
        archive.maven_package_roots = vec!["org/example/library".to_owned()];
        let result = classify(ScopeClassificationInput {
            archives: vec![archive],
            classes: vec![ClassScopeInput {
                archive_id: "nested".to_owned(),
                class_name: "org/example/library/Decoder".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::BundledDependency);
        assert_eq!(result.reason, ClassificationReason::MavenPackage);
    }

    #[test]
    fn generated_classes_do_not_affect_first_party_obfuscation_metrics() {
        let result = classify(ScopeClassificationInput {
            archives: vec![archive("root", 0, None, false, &[])],
            classes: vec![ClassScopeInput {
                archive_id: "root".to_owned(),
                class_name: "example/mod/Handler$$Lambda$42".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::GeneratedCode);
        assert_eq!(result.reason, ClassificationReason::GeneratedClass);
    }

    #[test]
    fn root_archive_uses_dominant_package_root_when_metadata_is_missing() {
        let result = classify(ScopeClassificationInput {
            archives: vec![archive("root", 0, None, false, &[])],
            classes: vec![ClassScopeInput {
                archive_id: "root".to_owned(),
                class_name: "dev/example/mod/Feature".to_owned(),
            }],
            dominant_package_roots: vec!["dev.example.mod".to_owned()],
        });

        assert_eq!(result.scope, CodeScope::FirstParty);
        assert_eq!(result.classification_confidence, Confidence::Medium);
        assert_eq!(result.reason, ClassificationReason::DominantRootPackage);
    }

    #[test]
    fn unknown_nested_archive_is_not_assumed_to_be_first_party() {
        let result = classify(ScopeClassificationInput {
            archives: vec![archive("nested", 1, None, false, &[])],
            classes: vec![ClassScopeInput {
                archive_id: "nested".to_owned(),
                class_name: "unattributed/payload/Loader".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::Unknown);
        assert_eq!(result.classification_confidence, Confidence::Medium);
        assert_eq!(result.reason, ClassificationReason::UnknownNestedArchive);
    }

    #[test]
    fn missing_archive_context_is_reported_explicitly() {
        let result = classify(ScopeClassificationInput {
            archives: Vec::new(),
            classes: vec![ClassScopeInput {
                archive_id: "gone".to_owned(),
                class_name: "example/mod/Loader".to_owned(),
            }],
            dominant_package_roots: Vec::new(),
        });

        assert_eq!(result.scope, CodeScope::Unknown);
        assert_eq!(result.classification_confidence, Confidence::Low);
        assert_eq!(result.reason, ClassificationReason::MissingArchiveMetadata);
    }
}
