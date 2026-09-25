# SARIF 2.1.0 JSON schema

`sarif-schema-2.1.0.json` is the official OASIS SARIF 2.1.0 JSON schema,
vendored unmodified so `tests/unit/test_sarif_validity.py` can validate the
SARIF reporter's output offline.

- Source: https://json.schemastore.org/sarif-2.1.0.json, the SchemaStore mirror
  of the OASIS SARIF Technical Committee schema (its `$id` is
  https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json).
- Retrieved: 2026-09-24.
- SHA-256: `c96eb2d311c37b0a38cbd18c52d79a68f778bbd2d831abed7412d9850740f785`.
- Licence: the schema is an OASIS SARIF TC work product governed by the OASIS
  Intellectual Property Rights Policy (RF on RAND Terms mode); see
  https://github.com/oasis-tcs/sarif-spec/blob/main/LICENSE.md. The SchemaStore
  catalogue that serves the mirror is licensed under Apache-2.0.

To refresh it, download the same URL again and update the checksum above. The
schema does not express every rule of the specification (for example that a
`region` must carry `startLine`, `charOffset` or `byteOffset`); those rules are
asserted directly by the test.
