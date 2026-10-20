# Offline follow-up trace, not an upload proof
Dependencies are the parent requirements.txt. Input ROOT layout:
- ROOT/raw/Wow.exe and ROOT/raw/wow_loader.dll (private, matching recorded hashes)
- ROOT/analysis/telemetry-descriptors.json (from preceding extraction)
- ROOT/trace/ (create empty output directory)

Run in order:
```
python inspect_options.py ROOT
python trace_references.py ROOT
python check_code_candidates.py ROOT
```
The scripts only read binaries; no target code is executed. Exact addresses/metadata are build-specific. The string search is case-sensitive, bounded to forty hits/needle and local context; failure to find a cleartext API name is not evidence it is unused. Absolute pointer matches and RIP instruction byte candidates can miss interior/pointer-indirect/encoded references. Unwind bounds are only containing ranges, not recovered semantic functions. Candidate validation does not evaluate conditions or follow calls, and an endpoint-reference graph reached the 12,000 instruction budget. Linear and branch-following disassembly can differ; no static reachability candidate is promoted to runtime invocation or dataflow proof. QA.json records seven offline consistency checks, not seven native Windows or game tests. No workflow runs these against uploaded proprietary binaries.
