# Offline PE + embedded telemetry schema inventory
No target code is executed. Supply your own matching retail binaries; they are not distributed in this repository.
```
python -m pip install -r requirements.txt
python static_inventory.py PRIVATE_INPUT_DIR PRIVATE_OUTPUT_DIR
python extract_telemetry_schema.py PRIVATE_INPUT_DIR/Wow.exe PRIVATE_OUTPUT_DIR/telemetry-descriptors.json
python -m unittest test_schema
```
PE imports/strings and RIP-relative byte candidates are NOT a recovered call graph or proof of upload. The candidate xref scanner supports x64 only and can start inside another instruction; per-function unwind ranges are not semantic validation. Native 32-bit files are inventoried but not xref-scanned. WOW .text entropy is near 8 bits/byte, with loader-dependent entry/imports; original source/full decompilation was NOT recovered. Embedded protobuf field structures are stronger than loose string hits, but do not prove population, serialization at runtime, routing, delivery or frequency. Dependency availability outside this environment is not guaranteed.
