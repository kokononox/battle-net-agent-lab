import ast
import copy
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('isolation_model', ROOT/'source/isolation_model.py')
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def assumptions():
    return m.Assumptions(*([True]*8))


def fixture(count=3, existing=False):
    rules = [m.Rule(f'r-{i:03d}', f'{i+1:064x}', True) for i in range(count)]
    rules += [m.Rule('disabled-before', 'd'*64, False), m.Rule('block-before', 'b'*64, True, action='Block')]
    transport = m.Rule('owned-transport', 'a'*64, False, transport_witness=True)
    if existing:
        rules += [replace(transport, enabled=True)]
        transport = None
    baseline = tuple(rules)
    return baseline, m.compile_model(baseline, assumptions(), transport)


def apply_memory(view, op):
    d = {r.ref: r for r in view}
    if d.get(op.ref) != op.before:
        raise AssertionError('memory_before_mismatch')
    if op.after is None:
        d.pop(op.ref, None)
    else:
        d[op.ref] = op.after
    return tuple(sorted(d.values(), key=lambda r: r.ref))


def advance(s, view):
    s = m.request_intent(s, view, target_quiescent=True, transport_current=True)
    s = m.confirm_intent_checkpoint(s, persisted_readback=True)
    op = m.model_write_precondition(s, view, target_quiescent=True, transport_current=True)
    view = apply_memory(view, op)
    s = m.acknowledge_observation(s, view)
    s = m.confirm_result_checkpoint(s, persisted_readback=True)
    return s, view


def start(plan):
    return m.open_model(plan, baseline_checkpoint_verified=True, explicit_model_consent=True)


class Tests(unittest.TestCase):
    def refuse(self, code, function, *args, **kw):
        with self.assertRaisesRegex(m.Refusal, '^'+code+'$'):
            function(*args, **kw)

    def test_all_precondition_failures(self):
        baseline, p = fixture()
        for name in assumptions().__dict__:
            with self.subTest(gate=name):
                self.refuse('model_missing_precondition', m.compile_model, baseline,
                            replace(assumptions(), **{name:False}), p.operations[0].after)
                self.refuse('model_missing_precondition', m.compile_model, baseline,
                            replace(assumptions(), **{name:1}), p.operations[0].after)

    def test_106_allow_fixture_not_user_inventory(self):
        baseline, p = fixture(106)
        summary = m.summarize(p)
        self.assertEqual(summary['foreign_allow_toggles'], 106)
        self.assertEqual(summary['new_transport_objects'], 1)
        self.assertEqual(summary['application_grants'], 0)
        self.assertEqual(summary['profile_default_changes'], 0)
        for key in ['plan_executable','ready_for_apply','target_execution_authorized','no_leak_certified']:
            self.assertIs(summary[key], False)
        self.assertEqual(p.operations[0].kind, 'create_transport_disabled')
        self.assertEqual(p.operations[1].kind, 'enable_transport')
        self.assertTrue(all(o.kind == 'disable_reviewed_foreign_allow' for o in p.operations[2:]))
        s = start(p); view = baseline
        while s.next_index < len(p.operations):
            s, view = advance(s, view)
        result = m.restricted_model_observation(s, view, transport_current=True)
        self.assertFalse(result['target_execution_authorized'])
        self.assertFalse(result['no_leak_certified'])
        self.assertEqual(next(r for r in view if r.ref == 'block-before'), next(r for r in baseline if r.ref == 'block-before'))
        self.assertFalse(next(r for r in view if r.ref == 'disabled-before').enabled)
        recovery = m.begin_recovery_model(s, view, explicit_recovery_consent=True, targets_and_helpers_quiescent=True)
        self.assertNotEqual(recovery.model_digest, p.model_digest)
        rs = start(recovery)
        while rs.next_index < len(recovery.operations):
            rs, view = advance(rs, view)
        self.assertTrue(m.restored_model_observation(rs, view, baseline)['model_baseline_restored'])
        self.assertFalse(m.restored_model_observation(rs, view, baseline)['normal_internet_restored'])

    def test_existing_transport_and_zero_foreign_allow(self):
        for n in [0,1,4]:
            baseline, p = fixture(n, existing=True)
            self.assertEqual(len(p.operations), n)
            self.assertFalse(any(o.kind.startswith('create') for o in p.operations))
            s = start(p); view = baseline
            while s.next_index < len(p.operations):
                s, view = advance(s, view)
            self.assertTrue(m.restricted_model_observation(s, view, transport_current=True)['model_restricted_predicate_matches'])

    def test_inventory_rejects_unknown_managed_and_collisions(self):
        b, p = fixture()
        t = p.operations[0].after
        for source in ['managed','unknown']:
            self.refuse('model_uncontrollable_effective_allow', m.compile_model,
                        (replace(b[0], source=source),)+b[1:], assumptions(), t)
        self.refuse('model_owned_ref_collision', m.compile_model, b, assumptions(), replace(t, ref=b[0].ref))
        self.refuse('model_missing_exact_transport', m.compile_model, b, assumptions())
        self.refuse('model_duplicate_ref', m.compile_model, b+(b[0],), assumptions(), t)
        self.refuse('model_fingerprint', m.compile_model, (replace(b[0], fingerprint='bad'),)+b[1:], assumptions(), t)
        self.refuse('model_boolean', m.compile_model, (replace(b[0], enabled=1),)+b[1:], assumptions(), t)
        self.refuse('model_transport_shape', m.compile_model, b, assumptions(), replace(t, enabled=True))
        self.refuse('model_transport_shape', m.compile_model, b, assumptions(), replace(t, action='Block'))
        existing, _ = fixture(existing=True)
        self.refuse('model_duplicate_transport_path', m.compile_model, existing, assumptions(), t)

    def test_journal_order_consent_and_readback(self):
        b,p=fixture()
        for consent, saved in [(False,True),(True,False),(True,1)]:
            self.refuse('model_no_baseline_or_consent', m.open_model,p,
                        baseline_checkpoint_verified=saved,explicit_model_consent=consent)
        s=start(p)
        self.refuse('model_no_committed_intent',m.model_write_precondition,s,b,target_quiescent=True,transport_current=True)
        self.refuse('model_not_finished',m.restricted_model_observation,s,b,transport_current=True)
        for q,t in [(False,True),(True,False)]:
            self.refuse('model_safety_observation_missing',m.request_intent,s,b,target_quiescent=q,transport_current=t)
        s=m.request_intent(s,b,target_quiescent=True,transport_current=True)
        self.refuse('model_intent_not_durable',m.confirm_intent_checkpoint,s,persisted_readback=False)
        self.refuse('model_no_committed_intent',m.model_write_precondition,s,b,target_quiescent=True,transport_current=True)
        s=m.confirm_intent_checkpoint(s,persisted_readback=True)
        self.refuse('model_transition_order',m.confirm_intent_checkpoint,s,persisted_readback=True)
        op=m.model_write_precondition(s,b,target_quiescent=True,transport_current=True)
        self.refuse('model_readback_mismatch',m.acknowledge_observation,s,b)
        v=apply_memory(b,op);s=m.acknowledge_observation(s,v)
        self.refuse('model_result_not_durable',m.confirm_result_checkpoint,s,persisted_readback=False)
        self.refuse('model_transition_order',m.request_intent,s,v,target_quiescent=True,transport_current=True)

    def test_drift_refuses_no_repair(self):
        b,p=fixture();s=start(p)
        for view in [b[1:],b+(m.Rule('unexpected','c'*64,True),),
                     (replace(b[0],fingerprint='e'*64),)+b[1:],(replace(b[0],enabled=False),)+b[1:]]:
            self.refuse('model_policy_drift',m.request_intent,s,view,target_quiescent=True,transport_current=True)
            self.refuse('model_recovery_drift_or_unreachable',m.recovery_preview,s,view,
                        explicit_recovery_consent=True,targets_and_helpers_quiescent=True)
        for consent,q in [(False,True),(True,False)]:
            self.refuse('model_recovery_consent_or_quiescence_missing',m.recovery_preview,s,b,
                        explicit_recovery_consent=consent,targets_and_helpers_quiescent=q)

    def test_crash_at_every_operation_and_ambiguous_write(self):
        # Independent in-memory fault injection, NOT power-loss durability on Windows.
        for existing in [False,True]:
            for count in [1,3,8]:
                baseline,p=fixture(count,existing)
                prefix_state=start(p);prefix_view=baseline
                for index in range(len(p.operations)):
                    intent=m.request_intent(prefix_state,prefix_view,target_quiescent=True,transport_current=True)
                    durable=m.confirm_intent_checkpoint(intent,persisted_readback=True)
                    op=m.model_write_precondition(durable,prefix_view,target_quiescent=True,transport_current=True)
                    after=apply_memory(prefix_view,op)
                    for effect in [False,True]:
                        with self.subTest(existing=existing,count=count,index=index,effect=effect):
                            view=after if effect else prefix_view
                            before_copy=copy.deepcopy(view)
                            inverse=m.recovery_preview(durable,view,explicit_recovery_consent=True,targets_and_helpers_quiescent=True)
                            for undo in inverse:
                                view=apply_memory(view,undo)
                            self.assertEqual({r.ref:r for r in view},{r.ref:r for r in baseline})
                            resumed, label=m.resume_pending_model(durable,before_copy)
                            self.assertEqual(label,'result_checkpoint_required' if effect else 'same_committed_intent_retry_possible')
                            self.assertEqual(resumed.observation_verified,effect)
                    # Result checkpoint failed after the write: durable intent, not next op.
                    observed=m.acknowledge_observation(durable,after)
                    self.refuse('model_result_not_durable',m.confirm_result_checkpoint,observed,persisted_readback=False)
                    prefix_state=m.confirm_result_checkpoint(observed,persisted_readback=True)
                    prefix_view=after

    def test_recovery_crash_resume_each_step(self):
        for existing in [False,True]:
            baseline,p=fixture(4,existing);s=start(p);view=baseline
            while s.next_index<len(p.operations):s,view=advance(s,view)
            rp=m.begin_recovery_model(s,view,explicit_recovery_consent=True,targets_and_helpers_quiescent=True)
            rs=start(rp)
            while rs.next_index<len(rp.operations):
                pending=m.request_intent(rs,view,target_quiescent=True,transport_current=True)
                pending=m.confirm_intent_checkpoint(pending,persisted_readback=True)
                op=m.model_write_precondition(pending,view,target_quiescent=True,transport_current=True)
                unchanged,label=m.resume_pending_model(pending,view)
                self.assertEqual(label,'same_committed_intent_retry_possible')
                view=apply_memory(view,op)
                resumed,label=m.resume_pending_model(pending,view)
                self.assertEqual(label,'result_checkpoint_required')
                # No duplicate setter after an observed effect; checkpoint first.
                self.refuse('model_no_committed_intent',m.model_write_precondition,resumed,view,
                            target_quiescent=True,transport_current=True)
                rs=m.confirm_result_checkpoint(resumed,persisted_readback=True)
            self.assertTrue(m.restored_model_observation(rs,view,baseline)['model_baseline_restored'])
            self.refuse('model_no_nested_recovery',m.begin_recovery_model,rs,view,
                        explicit_recovery_consent=True,targets_and_helpers_quiescent=True)

    def test_no_rollback_of_completed_prefix_in_forward_journal(self):
        b,p=fixture();s,v=advance(start(p),b)
        self.refuse('model_recovery_drift_or_unreachable',m.recovery_preview,s,b,
                    explicit_recovery_consent=True,targets_and_helpers_quiescent=True)

    def test_digest_and_no_input_mutation(self):
        b,p=fixture();before=copy.deepcopy(b)
        self.assertEqual(m.compile_model(tuple(reversed(b)),assumptions(),p.operations[0].after).model_digest,p.model_digest)
        altered=(replace(b[0],fingerprint='f'*64),)+b[1:]
        self.assertNotEqual(m.compile_model(altered,assumptions(),p.operations[0].after).model_digest,p.model_digest)
        self.assertEqual(b,before)
        self.assertNotIn('fingerprint',str(m.summarize(p)))
        self.assertNotIn('owned-transport',str(m.summarize(p)))

    def test_source_has_no_native_or_file_network_executor(self):
        tree=ast.parse((ROOT/'source/isolation_model.py').read_text())
        imports={n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)}
        imports|={a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names}
        self.assertEqual(imports,{'dataclasses','hashlib','json','re'})
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                self.assertNotIn(node.func.id,{'open','exec','eval','compile','__import__'})


if __name__ == '__main__':
    unittest.main()
