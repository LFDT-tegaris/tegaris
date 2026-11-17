use super::*;

fn id(n: u8) -> Uuid {
    Uuid::parse_str(&format!("01950000-0000-7000-8000-{n:012x}")).unwrap()
}
fn original() -> RetainedFactSource {
    RetainedFactSource {
        source_profile: id(1),
        plan: id(2),
        source_revision: 4,
        projection_revision: 5,
        qualification: id(3),
        validation: id(4),
        configuration: Digest::of(b"original configuration"),
        profile: Digest::of(b"original profile"),
        mapping: Digest::of(b"original mapping"),
        publication: Digest::of(b"original publication"),
        source_generation: id(5),
        partition: id(6),
    }
}
fn current(source: &RetainedFactSource) -> CurrentSource {
    CurrentSource {
        indexer: id(7),
        plan: source.plan,
        source_revision: source.source_revision,
        projection_revision: source.projection_revision,
        qualification: source.qualification,
        validation: source.validation,
        profile: source.profile.clone(),
        mapping: source.mapping.clone(),
        validation_configuration: source.configuration.clone(),
        active_configuration: source.configuration.clone(),
    }
}

#[test]
fn candidate_source_profile_never_substitutes_for_the_locked_control_indexer() {
    let original = original();
    let current = current(&original);
    assert_ne!(current.indexer, original.source_profile);
    assert!(current.matches(&original).is_ok());
}

#[test]
fn current_source_rejects_requalification_revalidation_or_configuration_change() {
    let original = original();
    for case in 0..9 {
        let mut changed = current(&original);
        match case {
            0 => changed.plan = id(11),
            1 => changed.source_revision += 1,
            2 => changed.projection_revision += 1,
            3 => changed.qualification = id(11),
            4 => changed.validation = id(11),
            5 => changed.profile = Digest::of(b"replacement"),
            6 => changed.mapping = Digest::of(b"replacement"),
            7 => changed.validation_configuration = Digest::of(b"replacement"),
            _ => changed.active_configuration = Digest::of(b"replacement"),
        }
        assert!(changed.matches(&original).is_err(), "case {case}");
    }
}

#[test]
fn one_plan_cannot_hide_conflicting_original_publications_during_deduplication() {
    let original = original();
    for case in 0..10 {
        let mut changed = original.clone();
        match case {
            0 => changed.source_profile = id(11),
            1 => changed.plan = id(11),
            2 => changed.source_revision += 1,
            3 => changed.projection_revision += 1,
            4 => changed.qualification = id(11),
            5 => changed.validation = id(11),
            6 => changed.configuration = Digest::of(b"replacement"),
            7 => changed.profile = Digest::of(b"replacement"),
            8 => changed.mapping = Digest::of(b"replacement"),
            _ => changed.publication = Digest::of(b"replacement"),
        }
        assert!(
            require_same_source(&original, &changed).is_err(),
            "case {case}"
        );
    }
    let mut different_partition = original.clone();
    different_partition.partition = id(12);
    assert!(require_same_source(&original, &different_partition).is_ok());
}

#[test]
fn provider_custody_can_shorten_but_never_refresh_the_original_deadline() {
    assert_eq!(qualified_deadline(100, 2, &[500, 600]).unwrap(), 100);
    assert_eq!(qualified_deadline(100, 2, &[70, 90]).unwrap(), 70);
    assert!(qualified_deadline(100, 2, &[90]).is_err());
    assert!(qualified_deadline(100, 1, &[-1]).is_err());
    assert!(qualified_deadline(100, 1, &[0]).is_err());
    assert!(qualified_deadline(100, 0, &[90]).is_err());
    assert!(qualified_deadline(0, 1, &[90]).is_err());
}

#[test]
fn replay_can_only_restrict_live_custody_to_its_recorded_original_deadline() {
    assert_eq!(shortened_deadline(100, 70).unwrap(), 70);
    assert_eq!(shortened_deadline(70, 70).unwrap(), 70);
    assert!(shortened_deadline(70, 100).is_err());
    assert!(shortened_deadline(70, 0).is_err());
    assert!(shortened_deadline(0, 1).is_err());
}
