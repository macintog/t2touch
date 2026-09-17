# Repository instructions

Read and follow [the project scope requirements](docs/PROJECT_SCOPE.md) and
[contribution guidance](CONTRIBUTING.md) before making changes.

Scope is a release gate. Do not put unrelated machine or distribution repairs
into T2Touch because they were found during its testing. Give those findings a
separate, documented disposition with evidence, ownership, and rollback.
Local repair authorization is not authorization to ship a product feature.
T2Touch must safely account for its own previously installed changes without
adopting unrelated local configuration. See PROJECT_SCOPE.md for the full rules.
