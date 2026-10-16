"""Official metadata -> complete Encoding/catalog binding -> conditional plan.

No game files are downloaded or written. Existing cache candidates are a separate
read-only evidence operation. No claim of a complete local CASC scan is made.
"""
import threading
import repair_core as core
import target_metadata as metadata
import plan_storage as store
import encoding_inventory
import catalog_inventory
import content_plan


def prepare(lab, download_inventory_path, profile=None, transport=None,
            cancel=None, notify=lambda _: None):
    cancel = cancel or threading.Event()
    transport = transport or core.HTTPS()
    with lab.lock(), store.input_db(lab, download_inventory_path) as (_, binding):
        target = metadata.discover(transport, cancel)
        expected = ("wow", "eu", target.version, target.build_config, target.cdn_config)
        if store.binding_id(binding) != expected:
            raise core.RepairError("download_inventory_not_current_selected_target")
        build, cdn = metadata.load_configs(target, transport, cancel)
        spec = metadata.manifest_spec(target, build, "encoding")
        notify("Receiving/verifying Encoding metadata; no game asset downloads.")
        decoded = core.fetch_decoded(lab, spec, transport, cancel)
        en_summary, en_path = encoding_inventory.build(
            lab, decoded, spec, dict(binding, encoding_ckey=spec.ckey,
                                    encoding_ekey=spec.ekey), cancel, notify)
        sources = catalog_inventory.acquire(
            lab, target.origins[0], cdn, transport, cancel, notify)
        cat_summary, cat_path = catalog_inventory.build(
            lab, sources, cdn.get("archives", []), binding, cancel, notify)
        plan_summary, plan_path = content_plan.build(
            lab, download_inventory_path, en_path, cat_path, profile, cancel, notify)
        after = metadata.discover(transport, cancel)
        if target.identity() != after.identity() or target.origins[0] not in after.origins:
            raise core.RepairError("official_target_changed_refresh_required")
        return {
            "target_version": target.version, "official_target_rechecked": True,
            "encoding": en_summary, "catalogs": cat_summary, "plan": plan_summary,
            "game_assets_downloaded": False, "game_files_modified": False,
            "installation_ready": False,
        }, plan_path