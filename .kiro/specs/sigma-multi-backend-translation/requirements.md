# Requirements Document

## Introduction

Fitur ini menambahkan workflow GitHub Actions yang secara otomatis menerjemahkan
seluruh rule Sigma dari folder `sigma/windows/`, `sigma/linux/`, `sigma/network/`,
dan `sigma/cloud/` ke berbagai backend SIEM (Elastic ES-QS, Elastic Lucene,
Elastic EQL, Splunk SPL, Microsoft Sentinel KQL, dan QRadar AQL sebagai backend
wajib; CrowdStrike, Sumo Logic, dan Devo sebagai backend opsional best-effort)
dan mem-publish hasilnya sebagai artifact rilis. Tujuannya adalah end-user dapat
langsung memakai query yang sudah dikonversi tanpa perlu meng-install
`sigma-cli` secara lokal.

Workflow ini berjalan otomatis ketika tag rilis `v*.*.*` di-push dan dapat
dipicu manual via `workflow_dispatch`. Setiap backend menghasilkan paket
zip/tar yang strukturnya mirror folder source (`windows/`, `linux/`, `network/`,
`cloud/`) plus manifest JSON yang melaporkan rule mana berhasil dan mana gagal
per-backend, sehingga proses transparan. Kegagalan konversi pada satu rule tidak
boleh menggagalkan seluruh build. Artifact terbaru juga dipublish ke GitHub
Pages agar tersedia URL stabil "latest".

Workflow harus reproducible: versi `sigma-cli` dan setiap plugin backend
di-pin lewat requirements file. Seluruh teks user-facing (release notes,
manifest catatan, file README di dalam artifact) menggunakan Bahasa Indonesia
sesuai konvensi `README.md` utama repo.

## Glossary

- **Sigma_Translator**: Job/step di GitHub Actions yang memanggil `sigma-cli` untuk mengonversi file Sigma ke target backend tertentu.
- **Release_Workflow**: Workflow GitHub Actions baru (file `.github/workflows/sigma-translate.yml`) yang men-orchestrate translasi, packaging, upload artifact, dan publish ke Pages.
- **Source_Folders**: Empat folder berisi rule Sigma yang menjadi input: `sigma/windows/`, `sigma/linux/`, `sigma/network/`, `sigma/cloud/`.
- **Mandatory_Backend**: Backend SIEM yang wajib didukung dengan kontrak gagal-build jika translator-nya error global. Daftar: Elastic ES-QS, Elastic Lucene, Elastic EQL, Splunk SPL, Microsoft Sentinel KQL, QRadar AQL.
- **Optional_Backend**: Backend SIEM yang dukungannya best-effort, di mana kegagalan global plugin TIDAK menggagalkan build. Daftar: CrowdStrike, Sumo Logic, Devo.
- **Backend_Artifact**: Paket zip dan tar.gz per-backend yang berisi hasil konversi dengan struktur folder mirror Source_Folders.
- **Conversion_Manifest**: File `manifest.json` per-backend yang mencantumkan daftar rule input, status hasil (`success` atau `failed`), pesan error untuk yang gagal, versi `sigma-cli`, versi plugin, dan timestamp.
- **Release_Tag**: Git tag yang cocok pola `v*.*.*` (contoh `v1.2.0`) yang memicu workflow secara otomatis.
- **Manual_Trigger**: Eksekusi workflow lewat `workflow_dispatch` di tab Actions GitHub, dengan input opsional `tag` untuk dry-run.
- **Pages_Latest_Path**: Path stabil di GitHub Pages (`/sigma-converted/latest/`) yang selalu menunjuk ke artifact dari rilis paling baru.
- **Requirements_File**: File `requirements-sigma.txt` di root repo yang mem-pin versi `sigma-cli` dan setiap plugin backend.
- **Conversion_Failure**: Kondisi di mana `sigma-cli` mengembalikan exit code non-zero atau menulis error untuk satu rule tertentu, tetapi backend secara keseluruhan masih dapat menghasilkan output untuk rule lain.

## Requirements

### Requirement 1: Pemicu Workflow

**User Story:** Sebagai release engineer, saya ingin translasi Sigma berjalan otomatis pada rilis dan bisa dipicu manual, supaya artifact tersedia tepat waktu tanpa langkah manual tambahan.

#### Acceptance Criteria

1. WHEN a Git tag matching the pattern `v*.*.*` is pushed, THE Release_Workflow SHALL start automatically.
2. WHEN a maintainer triggers `workflow_dispatch` from the Actions tab, THE Release_Workflow SHALL start with an optional `tag` input that defaults to `v0.0.0-dev`.
3. THE Release_Workflow SHALL read Source_Folders `sigma/windows/`, `sigma/linux/`, `sigma/network/`, and `sigma/cloud/` as the only translation inputs.
4. IF the workflow is triggered by a push event that is not a tag matching `v*.*.*`, THEN THE Release_Workflow SHALL exit without running translation steps.

### Requirement 2: Mandatory Backend Coverage

**User Story:** Sebagai detection engineer, saya ingin setiap rule Sigma diterjemahkan ke semua backend SIEM utama, supaya saya bisa pakai langsung di SIEM saya.

#### Acceptance Criteria

1. THE Sigma_Translator SHALL produce output for each Mandatory_Backend: Elastic ES-QS, Elastic Lucene, Elastic EQL, Splunk SPL, Microsoft Sentinel KQL, and QRadar AQL.
2. FOR each Mandatory_Backend, THE Sigma_Translator SHALL process every `.yml` file in Source_Folders and write the converted query to a Backend_Artifact.
3. WHEN at least one rule for a Mandatory_Backend converts successfully, THE Release_Workflow SHALL treat that backend as `partial_success` or `success` and continue.
4. IF the plugin for a Mandatory_Backend fails to install or produces zero successful conversions across all Source_Folders, THEN THE Release_Workflow SHALL fail the job for that backend with a non-zero exit code.

### Requirement 3: Optional Backend Coverage

**User Story:** Sebagai detection engineer yang pakai SIEM non-mainstream, saya ingin best-effort artifact untuk CrowdStrike, Sumo Logic, dan Devo, supaya saya tetap dapat output meskipun plugin upstream-nya kurang stabil.

#### Acceptance Criteria

1. THE Sigma_Translator SHALL attempt to produce output for each Optional_Backend: CrowdStrike, Sumo Logic, and Devo.
2. IF the plugin for an Optional_Backend fails to install or produces zero successful conversions, THEN THE Release_Workflow SHALL log a GitHub Actions warning, mark that backend as `skipped` in the Conversion_Manifest, and continue without failing the job.
3. WHERE an Optional_Backend produces at least one successful conversion, THE Release_Workflow SHALL package the partial Backend_Artifact identically to a Mandatory_Backend artifact.

### Requirement 4: Per-Rule Failure Isolation

**User Story:** Sebagai release engineer, saya ingin satu rule yang gagal dikonversi tidak membatalkan seluruh build, supaya rilis tetap jalan dengan rule yang valid.

#### Acceptance Criteria

1. WHEN a Conversion_Failure occurs for a single rule on any backend, THE Sigma_Translator SHALL skip that rule, log a warning that includes the rule file path and the error message, and continue translating the remaining rules.
2. THE Sigma_Translator SHALL record every skipped rule in the Conversion_Manifest with status `failed` and the captured error message.
3. THE Release_Workflow SHALL exit with status code 0 (success) when every Mandatory_Backend has at least one successfully converted rule, regardless of how many individual rules were skipped.

### Requirement 5: Mirror Folder Structure in Artifacts

**User Story:** Sebagai end-user yang download artifact, saya ingin struktur folder hasil konversi sama dengan source Sigma, supaya saya gampang menemukan rule per kategori.

#### Acceptance Criteria

1. FOR each backend produced, THE Sigma_Translator SHALL place converted output under subfolders `windows/`, `linux/`, `network/`, and `cloud/` matching Source_Folders.
2. WHERE a Source_Folder contains zero rules, THE Sigma_Translator SHALL still create the corresponding empty subfolder in the Backend_Artifact.
3. THE Sigma_Translator SHALL preserve each input rule's base filename and replace only the `.yml` extension with the backend-native extension (`.lucene`, `.eql`, `.spl`, `.kql`, `.aql`, `.cs`, `.sumo`, `.devo`).

### Requirement 6: Conversion Manifest

**User Story:** Sebagai detection engineer, saya ingin laporan transparan tentang rule mana berhasil dan gagal per backend, supaya saya tahu apa yang aman dipakai dan apa yang perlu di-review.

#### Acceptance Criteria

1. FOR each backend, THE Sigma_Translator SHALL write a `manifest.json` at the root of the Backend_Artifact.
2. THE Conversion_Manifest SHALL include the fields `backend`, `sigma_cli_version`, `plugin_version`, `generated_at` (ISO 8601 UTC timestamp), `release_tag`, `total_rules`, `succeeded`, `failed`, and `rules` (array).
3. FOR each entry in the `rules` array, THE Conversion_Manifest SHALL include `path` (relative to repo root), `status` (`success` or `failed`), `output_file` (relative to artifact root, omitted when status is `failed`), and `error` (string, present only when status is `failed`).
4. THE Conversion_Manifest SHALL be valid JSON and parseable by `jq empty` without errors.

### Requirement 7: Artifact Packaging and Release Attachment

**User Story:** Sebagai end-user, saya ingin satu paket zip dan tar.gz per backend yang attach ke GitHub Release, supaya saya bisa download yang relevan untuk SIEM saya saja.

#### Acceptance Criteria

1. FOR each backend that produces output, THE Release_Workflow SHALL create both a `.zip` and a `.tar.gz` archive named `sigma-converted-<backend>-<release_tag>.zip` and `sigma-converted-<backend>-<release_tag>.tar.gz`.
2. THE Release_Workflow SHALL generate a `checksums.txt` file at the workflow root containing SHA-256 hashes of every produced archive.
3. WHEN running on a Release_Tag trigger, THE Release_Workflow SHALL attach every produced archive plus `checksums.txt` to the corresponding GitHub Release using `softprops/action-gh-release`.
4. WHEN running on a Manual_Trigger that did not push a tag, THE Release_Workflow SHALL upload the archives as workflow artifacts via `actions/upload-artifact` and SHALL NOT modify any GitHub Release.

### Requirement 8: GitHub Pages Latest Mirror

**User Story:** Sebagai user dokumentasi, saya ingin URL stabil yang selalu menunjuk ke artifact terbaru, supaya tautan di README atau script automation tidak putus tiap rilis.

#### Acceptance Criteria

1. WHEN the Release_Workflow completes successfully on a Release_Tag trigger, THE Release_Workflow SHALL publish all Backend_Artifact archives plus their `manifest.json` files to the Pages_Latest_Path `/sigma-converted/latest/` on GitHub Pages.
2. THE Release_Workflow SHALL also publish a copy under `/sigma-converted/<release_tag>/` to preserve historical access.
3. THE Pages_Latest_Path SHALL include an `index.json` listing each backend, the artifact archive URLs, the manifest URL, and the release tag.
4. IF the GitHub Pages publish step fails, THEN THE Release_Workflow SHALL log a warning, leave the GitHub Release artifacts intact, and exit with success.

### Requirement 9: Reproducible Pinned Dependencies

**User Story:** Sebagai maintainer, saya ingin versi sigma-cli dan plugin di-pin, supaya hasil translasi reproducible dan tidak berubah karena update upstream tanpa kontrol.

#### Acceptance Criteria

1. THE Release_Workflow SHALL install dependencies exclusively from the Requirements_File `requirements-sigma.txt` checked into the repo root.
2. THE Requirements_File SHALL pin `sigma-cli` and every backend plugin to an exact version using the `==` operator.
3. WHEN a maintainer updates the Requirements_File, THE Release_Workflow SHALL fail if the file uses any version specifier other than `==` (no `>=`, `~=`, or unbounded names).
4. THE Conversion_Manifest SHALL reflect the exact `sigma_cli_version` and `plugin_version` resolved from the Requirements_File at runtime.

### Requirement 10: User-Facing Bahasa Indonesia

**User Story:** Sebagai end-user repo Detection-Rules, saya ingin teks rilis dan manifest dalam Bahasa Indonesia, supaya konsisten dengan README utama repo.

#### Acceptance Criteria

1. THE Release_Workflow SHALL generate a `RELEASE_NOTES_SIGMA.md` file inside each Backend_Artifact written in Bahasa Indonesia.
2. THE `RELEASE_NOTES_SIGMA.md` SHALL contain the sections "Ringkasan", "Cara Pakai", "Daftar Rule Berhasil", and "Daftar Rule Gagal".
3. WHERE the Release_Workflow appends notes to the GitHub Release body, THE Release_Workflow SHALL use Bahasa Indonesia for all custom text it adds.
4. THE Conversion_Manifest field names SHALL remain in English to preserve machine-readability while any free-text `error` and `notes` fields SHALL use the original tool output verbatim without translation.

### Requirement 11: Failure Reporting and Observability

**User Story:** Sebagai maintainer, saya ingin melihat ringkasan kegagalan langsung di summary GitHub Actions, supaya saya bisa cepat mengidentifikasi backend yang bermasalah.

#### Acceptance Criteria

1. WHEN the Release_Workflow finishes, THE Release_Workflow SHALL append a markdown summary to `$GITHUB_STEP_SUMMARY` listing every backend with columns: backend name, total rules, succeeded count, failed count, and status (`success`, `partial_success`, `skipped`, or `failed`).
2. WHEN any Mandatory_Backend has zero successful conversions, THE Release_Workflow SHALL set the job status to failed and include the corresponding row in the summary marked `failed`.
3. THE Release_Workflow SHALL log every per-rule Conversion_Failure as a GitHub Actions warning annotation that points to the rule file path.
