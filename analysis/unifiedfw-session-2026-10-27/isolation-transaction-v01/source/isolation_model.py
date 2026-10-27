"""OFFLINE MODEL ONLY. No native adapter, IO, executor or authorization capability.
Witnesses are model assumptions, never evidence obtained from Windows.
Rule snapshots here have opaque fixture fingerprints, not restorable native exports.
"""
from dataclasses import dataclass, replace
import hashlib
import json
import re


class Refusal(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Refusal(code)


@dataclass(frozen=True)
class Rule:
    ref: str
    fingerprint: str  # all immutable rule/filter properties, NOT just display name
    enabled: bool
    action: str = 'Allow'
    source: str = 'local'
    transport_witness: bool = False  # fictional model witness, not imported approval


@dataclass(frozen=True)
class Assumptions:
    profiles_enabled_block: bool
    full_inventory_and_filters: bool
    effective_local_correlation: bool
    target_and_helpers_quiescent: bool
    exact_transport_reviewed: bool
    cold_bootstrap_dependencies_reviewed: bool
    independent_recovery_reviewed: bool
    effective_policy_ownership_reviewed: bool


@dataclass(frozen=True)
class Operation:
    kind: str
    before: Rule | None
    after: Rule | None

    @property
    def ref(self):
        return (self.before or self.after).ref

    def inverse(self):
        return Operation('restore_' + self.kind, self.after, self.before)


@dataclass(frozen=True)
class Plan:
    baseline: tuple[Rule, ...]
    operations: tuple[Operation, ...]
    model_digest: str
    plan_executable: bool = False
    ready_for_apply: bool = False
    native_identity_verified: bool = False
    no_leak_certified: bool = False


def validate_rules(rules):
    require(type(rules) is tuple and len(rules) <= 4096, 'model_inventory_shape')
    refs = set()
    for r in rules:
        require(type(r) is Rule, 'model_rule_type')
        require(type(r.ref) is str and re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', r.ref), 'model_rule_ref')
        require(r.ref not in refs, 'model_duplicate_ref')
        refs.add(r.ref)
        require(type(r.fingerprint) is str and re.fullmatch(r'[a-f0-9]{64}', r.fingerprint), 'model_fingerprint')
        require(type(r.enabled) is bool and type(r.transport_witness) is bool, 'model_boolean')
        require(r.action in ('Allow', 'Block') and r.source in ('local', 'managed', 'unknown'), 'model_rule_shape')
    return {r.ref: r for r in rules}


def compile_model(baseline, assumptions, proposed_transport=None):
    """Preview a capture-only restricted phase: ZERO application grants.
    Only the current Block baseline is supported; no profile default is changed.
    Every changed foreign rule is toggled only; never deleted or recreated.
    """
    existing = validate_rules(baseline)
    require(type(assumptions) is Assumptions, 'model_assumptions_type')
    require(all(type(v) is bool and v for v in assumptions.__dict__.values()), 'model_missing_precondition')
    active = [r for r in baseline if r.enabled and r.action == 'Allow']
    require(all(r.source == 'local' for r in active), 'model_uncontrollable_effective_allow')
    transport = [r for r in active if r.transport_witness]
    ops = []
    if proposed_transport is not None:
        validate_rules((proposed_transport,))
        require(not transport, 'model_duplicate_transport_path')
        require(proposed_transport.ref not in existing, 'model_owned_ref_collision')
        require(proposed_transport.source == 'local' and proposed_transport.action == 'Allow'
                and not proposed_transport.enabled and proposed_transport.transport_witness,
                'model_transport_shape')
        ops += [Operation('create_transport_disabled', None, proposed_transport),
                Operation('enable_transport', proposed_transport, replace(proposed_transport, enabled=True))]
    else:
        require(bool(transport), 'model_missing_exact_transport')
    for rule in sorted(active, key=lambda r: r.ref):
        if not rule.transport_witness:
            ops.append(Operation('disable_reviewed_foreign_allow', rule, replace(rule, enabled=False)))
    # Digest detects content changes within this model, not consent/signature/anti-rollback.
    value = {'baseline': [r.__dict__ for r in sorted(baseline, key=lambda r: r.ref)],
             'assumptions': assumptions.__dict__,
             'operations': [{'kind': o.kind, 'before': None if o.before is None else o.before.__dict__,
                             'after': None if o.after is None else o.after.__dict__} for o in ops]}
    digest = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return Plan(tuple(sorted(baseline, key=lambda r: r.ref)), tuple(ops), digest)


@dataclass(frozen=True)
class ModelState:
    plan: Plan
    expected: tuple[Rule, ...]
    next_index: int = 0
    pending_index: int | None = None
    intent_committed: bool = False
    observation_verified: bool = False
    baseline_checkpoint_verified: bool = False
    explicit_model_consent: bool = False
    closed: bool = False
    # Intents persist before a possible effect. Never use only a success counter in recovery.
    intent_indices: tuple[int, ...] = ()


def open_model(plan, *, baseline_checkpoint_verified, explicit_model_consent):
    require(type(plan) is Plan and not plan.plan_executable and not plan.ready_for_apply, 'model_plan_only')
    require(baseline_checkpoint_verified is True and explicit_model_consent is True, 'model_no_baseline_or_consent')
    return ModelState(plan, plan.baseline, baseline_checkpoint_verified=True, explicit_model_consent=True)


def observe_exact(state, observed):
    require(validate_rules(observed) == validate_rules(state.expected), 'model_policy_drift')


def request_intent(state, observed, *, target_quiescent, transport_current):
    require(not state.closed and state.pending_index is None, 'model_transition_order')
    require(state.baseline_checkpoint_verified and state.explicit_model_consent, 'model_no_baseline_or_consent')
    require(target_quiescent is True and transport_current is True, 'model_safety_observation_missing')
    observe_exact(state, observed)
    require(state.next_index < len(state.plan.operations), 'model_no_next_operation')
    return replace(state, pending_index=state.next_index, intent_committed=False, observation_verified=False)


def confirm_intent_checkpoint(state, *, persisted_readback):
    require(state.pending_index is not None and not state.intent_committed, 'model_transition_order')
    require(persisted_readback is True, 'model_intent_not_durable')
    return replace(state, intent_committed=True, intent_indices=state.intent_indices+(state.pending_index,))


def model_write_precondition(state, observed, *, target_quiescent, transport_current):
    """Checks an IN-MEMORY model transition; performs absolutely no write."""
    require(state.pending_index is not None and state.intent_committed and not state.observation_verified, 'model_no_committed_intent')
    require(target_quiescent is True and transport_current is True, 'model_safety_observation_missing')
    observe_exact(state, observed)
    return state.plan.operations[state.pending_index]


def acknowledge_observation(state, observed):
    require(state.pending_index is not None and state.intent_committed and not state.observation_verified, 'model_transition_order')
    op = state.plan.operations[state.pending_index]
    after = validate_rules(state.expected).copy()
    require(after.get(op.ref) == op.before, 'model_operation_before_mismatch')
    if op.after is None:
        after.pop(op.ref, None)
    else:
        after[op.ref] = op.after
    desired = tuple(sorted(after.values(), key=lambda r: r.ref))
    require(validate_rules(observed) == after, 'model_readback_mismatch')
    return replace(state, expected=desired, observation_verified=True)


def confirm_result_checkpoint(state, *, persisted_readback):
    require(state.observation_verified and state.pending_index is not None, 'model_transition_order')
    require(persisted_readback is True, 'model_result_not_durable')
    return replace(state, next_index=state.pending_index+1, pending_index=None,
                   intent_committed=False, observation_verified=False)


def restricted_model_observation(state, observed, *, transport_current):
    require(state.next_index == len(state.plan.operations) and state.pending_index is None, 'model_not_finished')
    require(transport_current is True, 'model_transport_not_current')
    observe_exact(state, observed)
    remaining = [r for r in observed if r.enabled and r.action == 'Allow']
    require(bool(remaining) and all(r.transport_witness for r in remaining), 'model_nontransport_allow_remaining')
    return {'model_restricted_predicate_matches': True, 'target_execution_authorized': False,
            'ready_for_apply': False, 'no_leak_certified': False, 'packet_enforcement_verified': False}


def recovery_preview(state, observed, *, explicit_recovery_consent, targets_and_helpers_quiescent):
    """Reconcile only intents, including write-before-crash and no-write cases.
    The entire observed model must be a reachable prefix. No unknown drift repair.
    Normal-network exit is NOT recovery: baseline Block and disabled rules stay so.
    """
    require(explicit_recovery_consent is True and targets_and_helpers_quiescent is True,
            'model_recovery_consent_or_quiescence_missing')
    current = validate_rules(observed)
    candidate = validate_rules(state.plan.baseline).copy()
    prefixes = [(candidate.copy(), ())]
    applied = []
    for index in state.intent_indices:
        require(type(index) is int and index == len(applied) and index < len(state.plan.operations), 'model_intent_sequence')
        op = state.plan.operations[index]
        require(candidate.get(op.ref) == op.before, 'model_recovery_chain')
        if op.after is None:
            candidate.pop(op.ref, None)
        else:
            candidate[op.ref] = op.after
        applied.append(op)
        prefixes.append((candidate.copy(), tuple(applied)))
    # Native integration must also anchor the journal's previously completed operations;
    # only the last outstanding intent may have no effect, not an arbitrary rollback.
    minimum = state.next_index
    matches = [(view, ops) for i, (view, ops) in enumerate(prefixes) if i >= minimum and view == current]
    require(len(matches) == 1, 'model_recovery_drift_or_unreachable')
    _, applied = matches[0]
    return tuple(op.inverse() for op in reversed(applied))


def summarize(plan):
    return {'schema': 'ufw-isolation-transaction-model-01', 'offline_model_only': True,
            'baseline_rule_count': len(plan.baseline),
            'foreign_allow_toggles': sum(o.kind == 'disable_reviewed_foreign_allow' for o in plan.operations),
            'new_transport_objects': sum(o.kind == 'create_transport_disabled' for o in plan.operations),
            'model_operation_count': len(plan.operations), 'application_grants': 0,
            'profile_default_changes': 0, 'plan_executable': False, 'ready_for_apply': False,
            'target_execution_authorized': False, 'no_leak_certified': False}


def begin_recovery_model(state, observed, *, explicit_recovery_consent, targets_and_helpers_quiescent):
    """Creates a SEPARATE model recovery transaction; journal it before its first intent.
    Resume that transaction's pending intent after another crash, never regenerate it.
    """
    require(not any(o.kind.startswith('restore_') for o in state.plan.operations), 'model_no_nested_recovery')
    ops = recovery_preview(state, observed, explicit_recovery_consent=explicit_recovery_consent,
                           targets_and_helpers_quiescent=targets_and_helpers_quiescent)
    content = {'mode': 'recovery', 'forward_model_digest': state.plan.model_digest,
               'observed': [r.__dict__ for r in sorted(observed, key=lambda r: r.ref)],
               'inverse_operations': [{'kind': o.kind,
                   'before': None if o.before is None else o.before.__dict__,
                   'after': None if o.after is None else o.after.__dict__} for o in ops]}
    digest = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    plan = Plan(tuple(sorted(observed, key=lambda r: r.ref)), ops, digest)
    # Baseline verification is NOT asserted here. Caller must explicitly model journal creation.
    return plan


def resume_pending_model(state, observed):
    """Reconcile one saved in-memory intent; never infers a write from success counts.
    After a failed result checkpoint, the old state is still the durable one.
    """
    require(state.pending_index is not None and state.intent_committed, 'model_no_committed_intent')
    if state.observation_verified:
        observe_exact(state, observed)
        return state, 'result_checkpoint_required'
    before = validate_rules(state.expected)
    current = validate_rules(observed)
    if current == before:
        return state, 'same_committed_intent_retry_possible'
    updated = acknowledge_observation(state, observed)
    return updated, 'result_checkpoint_required'


def restored_model_observation(state, observed, original_baseline):
    require(state.next_index == len(state.plan.operations) and state.pending_index is None, 'model_recovery_not_finished')
    observe_exact(state, observed)
    require(validate_rules(observed) == validate_rules(original_baseline), 'model_baseline_not_restored')
    return {'model_baseline_restored': True, 'normal_internet_restored': False,
            'original_profile_defaults_changed': False, 'native_restore_qualified': False}
