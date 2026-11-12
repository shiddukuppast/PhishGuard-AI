# PhishGuard AI — Dataset Quality, Bias and Leakage Audit

> **Scope:** Read-only validation and EDA only. No cleaning, imputation, balancing, feature engineering, splitting, model evaluation, or training was performed.

## Executive summary

The dataset has a severe collection-format confound. All 820 label-0 rows are scheme-less bare domains with no parsed path, while all 159,244 label-1 rows have an HTTP/HTTPS scheme; every label-0 row has `num_subdirs == 0`, while every label-1 row has `num_subdirs >= 2`. The latter feature is the raw slash count, so it directly captures the scheme marker and class-specific formatting. This is compelling evidence of a shortcut and dataset-construction bias, not proof that the labels themselves are wrong or that leakage was intentional.

The project files document label 0 as legitimate and label 1 as phishing, but the original dataset source, collection dates, labeling procedure, and row-level ground truth cannot be independently verified from repository evidence. The dataset should not be treated as a representative benchmark until provenance and the class-conditional URL format are resolved.

## 1. Dataset overview

- Shape: **160,064 rows × 13 columns**.
- Deep pandas memory usage: **41,562,194 bytes**.
- SHA-256 of the read-only source CSV: `1de48e23501c544b6d345fcdeca544c42f71ab10d3061e174b1d97feafc07db8`.
- Columns: `url`, `label`, `url_length`, `num_dots`, `has_https`, `has_ip`, `num_subdirs`, `num_params`, `suspicious_words`, `tld`, `special_char_count`, `digits_count`, `entropy`.

### Types, missingness and cardinality

| column | dtype | missing | unique_including_missing |
| --- | --- | --- | --- |
| url | str | 0 | 160064 |
| label | int64 | 0 | 2 |
| url_length | int64 | 0 | 521 |
| num_dots | int64 | 0 | 19 |
| has_https | int64 | 0 | 2 |
| has_ip | int64 | 0 | 2 |
| num_subdirs | int64 | 0 | 24 |
| num_params | int64 | 0 | 23 |
| suspicious_words | int64 | 0 | 4 |
| tld | str | 821 | 536 |
| special_char_count | int64 | 0 | 74 |
| digits_count | int64 | 0 | 180 |
| entropy | float64 | 0 | 43101 |

### Label meanings and provenance

- **Project-documented mapping:** label 0 = LEGITIMATE/BENIGN; label 1 = PHISHING. This appears in `model/README.md`, `model/artifacts/model_metadata.json`, and the label mapping in `model/Code/train.py`.
- **Not independently verified:** no upstream dataset URL, source citation, data dictionary, collection timestamp, annotation protocol, adjudication process, or committed dataset-construction script was found. The project README says benign examples came from top-domain rankings and phishing examples from active feeds, but does not identify those sources or document how labels were applied.
- **Conclusion:** retain the mapping as a project claim only; do not treat it as verified source provenance. The positive/negative meanings, timing, and label quality require owner confirmation.

## 2. Class imbalance

| label | rows | percent | meaning_in_project_docs |
| --- | --- | --- | --- |
| 0 | 820 | 0.5123 | LEGITIMATE (project-documented) |
| 1 | 159244 | 99.4877 | PHISHING (project-documented) |

- Majority/minority ratio: **194.20:1**.
- The small label-0 sample (820 rows) is insufficient to characterize the variety of benign URLs likely in deployment. Do not remove this minority class or balance the data before provenance and representativeness are resolved.

## 3. Missing-value analysis

| label | rows | missing_tld | missing_tld_percent |
| --- | --- | --- | --- |
| 0 | 820 | 820 | 100.0000 |
| 1 | 159244 | 1 | 0.0006 |

- Only `tld` is missing: 821 rows total. Missingness is class-concentrated: all 820 label-0 rows and 1 label-1 row.
- This makes missingness itself a near-deterministic label proxy. Existing training metadata describes filling categorical missing TLDs with `Unknown`; that would preserve the proxy rather than repair its cause.
- Do not impute or drop these rows until the source feature-generation logic is established. Keep explicit missingness and original values in any future derived dataset.

## 4. URL structure by class

| label | rows | mean_url_length | min_url_length | max_url_length | mean_num_subdirs | min_num_subdirs | max_num_subdirs | https_percent | ip_percent | query_count_percent | mean_entropy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 820 | 14.0780 | 6 | 22 | 0.0000 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 3.3554 |
| 1 | 159244 | 55.3187 | 12 | 25523 | 4.1497 | 2 | 104 | 43.6324 | 48.7974 | 9.9382 | 4.2507 |

### Parsed URL components

Parsing used Python `urllib.parse.urlsplit`, with scheme-less inputs interpreted as authorities (`//host`) for inspection. This is syntactic parsing, not DNS validation or a reachability check.

| label | parse_status | rows |
| --- | --- | --- |
| 0 | ok | 820 |
| 1 | ok | 159244 |

| label | scheme | rows | path_present | query_present | fragment_present | mean_path_segments | path_present_percent | query_present_percent | fragment_present_percent |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | NO_SCHEME | 820 | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 1 | http | 89762 | 89094 | 544 | 16 | 2.2606 | 99.2558 | 0.6060 | 0.0178 |
| 1 | https | 69482 | 68637 | 15229 | 340 | 1.7235 | 98.7839 | 21.9179 | 0.4893 |

- All 160,064 rows yielded a hostname under this parsing policy; no blank or parser-rejected URLs were found. Because URL parsers are permissive, this does not establish that each host is valid, resolvable, safe, or live.
- Label 0 is 100% scheme-less, pathless, queryless and fragmentless. Label 1 is 100% HTTP/HTTPS; 99.05% has a non-empty path, 9.90% a query, and 0.22% a fragment.
- The 820 label-0 URLs are 6–22 characters long; label 1 spans 12–25,523 characters. URL format is a major class confound.

## 5. Duplicate, variant and domain overlap analysis

- Exact duplicate rows: **0**.
- Exact duplicate URL strings: **0**.
- No empty or whitespace-only URL strings were found.

| normalization | duplicate_rows_after_first | duplicate_groups | mixed_label_groups |
| --- | --- | --- | --- |
| scheme-preserving (host case/IDNA/trailing dot/default port/empty path) | 93 | 93 | 0 |
| same key while ignoring scheme (diagnostic only) | 629 | 621 | 0 |

- Scheme-preserving normalization lowercases/IDNA-normalizes hostnames, removes trailing host dots and default ports, and maps an empty authority path to `/`; it preserves query, fragment and scheme. It finds 93 duplicate rows across 93 collision groups, with no mixed-label groups.
- Ignoring the scheme is a deliberately broader diagnostic (not a deduplication rule): it finds 629 duplicate rows across 621 groups, with no mixed-label groups. HTTP and HTTPS can be distinct resources; these collisions require review rather than automatic merging.
- Using the Public Suffix List snapshot `2026-11-11_17-18-20_UTC` (including ICANN and PRIVATE rules), registrable-domain/IP/single-label grouping found:

| measure | value |
| --- | --- |
| unique registrable-domain/IP/single-label groups | 42540.0 |
| repeated groups | 18946.0 |
| rows in repeated groups | 136470.0 |
| groups with both labels | 24.0 |
| rows in groups with both labels | 11423.0 |
| expected repeated groups crossing random 80/20 split | 8760.9 |
| expected rows in repeated groups crossing random 80/20 split | 111677.3 |

Largest groups containing both labels:

| registrable_domain | rows | label_count | labels |
| --- | --- | --- | --- |
| google.com | 7699 | 2 | {"1": 7695, "0": 4} |
| github.com | 1598 | 2 | {"1": 1597, "0": 1} |
| adobe.com | 1107 | 2 | {"1": 1106, "0": 1} |
| dropbox.com | 645 | 2 | {"1": 644, "0": 1} |
| archive.org | 72 | 2 | {"1": 71, "0": 1} |
| evernote.com | 57 | 2 | {"1": 56, "0": 1} |
| zoom.us | 56 | 2 | {"1": 55, "0": 1} |
| bitbucket.org | 56 | 2 | {"1": 55, "0": 1} |
| bing.com | 39 | 2 | {"1": 38, "0": 1} |
| booking.com | 35 | 2 | {"1": 34, "0": 1} |
| gitlab.com | 15 | 2 | {"1": 14, "0": 1} |
| ethz.ch | 7 | 2 | {"1": 6, "0": 1} |
| whimsical.com | 5 | 2 | {"1": 4, "0": 1} |
| mega.nz | 5 | 2 | {"1": 4, "0": 1} |
| monday.com | 4 | 2 | {"1": 3, "0": 1} |
| airtable.com | 3 | 2 | {"1": 2, "0": 1} |
| replit.com | 3 | 2 | {"1": 2, "0": 1} |
| huggingface.co | 3 | 2 | {"1": 2, "0": 1} |
| linkedin.com | 3 | 2 | {"1": 2, "0": 1} |
| pinterest.com | 3 | 2 | {"1": 2, "0": 1} |
| asana.com | 2 | 2 | {"1": 1, "0": 1} |
| robinhood.com | 2 | 2 | {"1": 1, "0": 1} |
| trendmicro.com | 2 | 2 | {"1": 1, "0": 1} |
| tiktok.com | 2 | 2 | {"1": 1, "0": 1} |

- Domains shared across labels may represent benign services hosting malicious content, mislabels, or shared infrastructure; they are not by themselves evidence of incorrect labels. They do show that domain-level grouping and review matter.
- Under an illustrative independent row-wise 80/20 split, approximately 8,761 repeated-domain groups would be expected to straddle both partitions, involving about 111,677 rows. This is a probability calculation, not an actual split or model evaluation.

### Near-duplicate pattern scan

| measure | value |
| --- | --- |
| repeated host/path templates | 6515 |
| rows in repeated templates | 23395 |
| templates containing both labels | 0 |

Candidate patterns below use the same hostname and path after replacing long numeric, UUID-like, and long hexadecimal path tokens; query values are omitted while parameter names are retained. This is a heuristic template scan, not edit-distance proof of duplicate content.

| template | rows | label_count |
| --- | --- | --- |
| 201.16.194.227/TmpFTP/EXTCONS/1/<NUM>/<HEX>/info.zip? | 1227 | 1 |
| 177.70.102.232/TmpFTP/TD<NUM>/info.zip? | 565 | 1 |
| 200.14.250.72/TmpFTP/DELCACHEPRODUTOSEG/1/<NUM>/<HEX>/info.zip? | 461 | 1 |
| 177.70.102.228/TmpFTP/TD<NUM>/info.zip? | 394 | 1 |
| img1.wsimg.com/blobby/go/<UUID>/downloads/<NUM>.pdf? | 381 | 1 |
| drive.google.com/uc?export&id | 261 | 1 |
| l.wl.co/l?u | 253 | 1 |
| eu.jotform.com/app/<HEX>? | 214 | 1 |
| app.jotform.com/<HEX>? | 168 | 1 |
| 201.16.194.227/TmpFTP/DELCACHEPRODUTOSEG/1/<NUM>/<HEX>/info.zip? | 116 | 1 |
| 104.0.237.199/NAS_Public/ken_l/RAX/Employee/sametimetranscripts/CN=Christina.Liserio%2COU=SAT%2COU/<NUM>/info.zip? | 58 | 1 |
| 104.0.237.199/NAS_Public/ken_l/RAX/Employee/sametimetranscripts/CN=ranjit.singh%2COU=SAT%2COU=Acco/<NUM>/info.zip? | 57 | 1 |
| forms.office.com/pages/responsepage.aspx?amp;fbclid&id | 53 | 1 |
| 104.0.237.199/NAS_Public/ken_l/RAX/Employee/sametimetranscripts/cn=jame<NUM>%2Cou=sat%2Cou=accounts/<NUM>/info.zip? | 49 | 1 |
| us6.campaign-archive.com/?id&u | 47 | 1 |
| us4.campaign-archive.com/?id&u | 45 | 1 |
| us20.campaign-archive.com/?id&u | 42 | 1 |
| us15.campaign-archive.com/?id&u | 42 | 1 |
| us9.campaign-archive.com/?id&u | 40 | 1 |
| us11.campaign-archive.com/?id&u | 39 | 1 |

## 6. Feature-level distributions and data quality

Per-feature unique-value counts and the ten most frequent values are shown below. `url` is a high-cardinality identifier (all values are unique), so its sample values are not a meaningful categorical distribution.

| feature | unique_including_missing | top_values_and_counts |
| --- | --- | --- |
| url_length | 521 | 34: 8918; 33: 8248; 28: 8170; 29: 7953; 35: 6199; 32: 5247; 30: 5201; 27: 4929; 22: 4752; 36: 3657 |
| num_dots | 19 | 4: 54712; 3: 48173; 2: 39331; 1: 13783; 5: 2276; 6: 1059; 7: 399; 13: 115; 8: 80; 10: 58 |
| has_https | 2 | 0: 90582; 1: 69482 |
| has_ip | 2 | 0: 82357; 1: 77707 |
| num_subdirs | 24 | 3: 96717; 4: 24865; 7: 11346; 8: 6636; 5: 6372; 6: 4474; 9: 3386; 10: 1855; 2: 1513; 0: 820 |
| num_params | 23 | 0: 144238; 1: 7523; 3: 4260; 2: 1957; 4: 1515; 5: 135; 10: 97; 7: 79; 9: 76; 8: 56 |
| suspicious_words | 4 | 0: 156650; 1: 3025; 2: 381; 3: 8 |
| tld | 536 | com: 32341; ru: 15011; 202: 3745; 34: 3551; 227: 3312; de: 2782; app: 2758; dev: 2691; me: 2549; 228: 2262 |
| special_char_count | 74 | 0: 98693; 1: 25591; 2: 10441; 4: 4709; 3: 4089; 6: 3649; 7: 2657; 8: 2329; 5: 1999; 10: 807 |
| digits_count | 180 | 0: 20524; 15: 13721; 16: 12336; 1: 9833; 14: 8933; 2: 8229; 3: 5936; 4: 5726; 17: 5675; 12: 5473 |
| entropy | 43101 | 3.939470994001287: 1094; 4.152391277629866: 1034; 4.0559581516151235: 924; 4.0614821867207755: 855; 3.936260027531527: 837; 3.9690016298759927: 690; 4.027169118440618: 682; 3.8442328987631917: 627; 3.7264741182543757: 558; 4.0060710131011685: 499 |

Numerical statistics exclude the target label:

| feature | count | mean | std | min | 1% | 25% | 50% | 75% | 95% | 99% | max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| url_length | 160064.0000 | 55.1074 | 101.7825 | 6.0000 | 21.0000 | 30.0000 | 37.0000 | 65.0000 | 155.0000 | 190.0000 | 25523.0000 |
| num_dots | 160064.0000 | 2.9990 | 1.1192 | 1.0000 | 1.0000 | 2.0000 | 3.0000 | 4.0000 | 4.0000 | 6.0000 | 59.0000 |
| has_https | 160064.0000 | 0.4341 | 0.4956 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| has_ip | 160064.0000 | 0.4855 | 0.4998 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| num_subdirs | 160064.0000 | 4.1284 | 2.0902 | 0.0000 | 2.0000 | 3.0000 | 3.0000 | 4.0000 | 8.0000 | 11.0000 | 104.0000 |
| num_params | 160064.0000 | 0.2215 | 0.9356 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 2.0000 | 4.0000 | 45.0000 |
| suspicious_words | 160064.0000 | 0.0238 | 0.1682 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 3.0000 |
| special_char_count | 160064.0000 | 1.4954 | 3.6996 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 8.0000 | 17.0000 | 264.0000 |
| digits_count | 160064.0000 | 12.7370 | 17.4206 | 0.0000 | 0.0000 | 3.0000 | 12.0000 | 16.0000 | 35.0000 | 51.3700 | 3413.0000 |
| entropy | 160064.0000 | 4.2461 | 0.4793 | 2.0588 | 3.4535 | 3.9077 | 4.1715 | 4.4849 | 5.1940 | 5.6127 | 6.0304 |

### Outlier screening

IQR counts are descriptive flags only; no rows were removed. The IQR rule is especially uninformative for zero-inflated features whose first and third quartiles are both zero.

| feature | q1 | median | q3 | p99 | max | iqr_lower | iqr_upper | iqr_outlier_rows | iqr_outlier_percent |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| url_length | 30.0000 | 37.0000 | 65.0000 | 190.0000 | 25523.0000 | -22.5000 | 117.5000 | 12907 | 8.0636 |
| num_dots | 2.0000 | 3.0000 | 4.0000 | 6.0000 | 59.0000 | -1.0000 | 7.0000 | 331 | 0.2068 |
| has_https | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | -1.5000 | 2.5000 | 0 | 0.0000 |
| has_ip | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 1.0000 | -1.5000 | 2.5000 | 0 | 0.0000 |
| num_subdirs | 3.0000 | 3.0000 | 4.0000 | 11.0000 | 104.0000 | 1.5000 | 5.5000 | 30597 | 19.1155 |
| num_params | 0.0000 | 0.0000 | 0.0000 | 4.0000 | 45.0000 | 0.0000 | 0.0000 | 15826 | 9.8873 |
| suspicious_words | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 3.0000 | 0.0000 | 0.0000 | 3414 | 2.1329 |
| special_char_count | 0.0000 | 0.0000 | 1.0000 | 17.0000 | 264.0000 | -1.5000 | 2.5000 | 25339 | 15.8305 |
| digits_count | 3.0000 | 12.0000 | 16.0000 | 51.3700 | 3413.0000 | -16.5000 | 35.5000 | 7199 | 4.4976 |
| entropy | 3.9077 | 4.1715 | 4.4849 | 5.6127 | 6.0304 | 3.0421 | 5.3505 | 6375 | 3.9828 |

The maximum URL length is driven by an exceptionally long URL with a large encoded HTML-like fragment; it is a candidate for manual source inspection, not an automatic outlier to delete. Several count features have long right tails and should be assessed within class and by source.

### Feature formula agreement with the committed extractor

Each stored feature was compared read-only against `model/Code/feature_extractor.py::extract_canonical_features` on the same raw URL. This checks consistency with the current project implementation, not correctness of the original labels or the upstream feature generator.

| feature | mismatches | mismatch_percent |
| --- | --- | --- |
| url_length | 0 | 0.0000 |
| num_dots | 0 | 0.0000 |
| has_https | 0 | 0.0000 |
| has_ip | 109 | 0.0681 |
| num_subdirs | 0 | 0.0000 |
| num_params | 347 | 0.2168 |
| suspicious_words | 878 | 0.5485 |
| tld | 78447 | 49.0098 |
| special_char_count | 16139 | 10.0828 |
| digits_count | 0 | 0.0000 |
| entropy | 0 | 0.0000 |

- Notable discrepancies: 78,447 stored `tld` values differ from the committed extractor; 16,139 `special_char_count`; 878 `suspicious_words`; 347 `num_params`; and 109 `has_ip` values differ. URL length, dot count, HTTPS flag, slash count, digits and rounded entropy agree on this comparison.
- The stored `tld` field has 536 distinct values, including 77,600 numeric values; 77,598 rows parse to IP-address hostnames. Numeric “TLDs” are not valid DNS TLD names and indicate an extraction/representation issue. All 820 label-0 TLDs are missing.
- The current extractor counts `=` among special characters; the observed mismatch is concentrated in that feature and must be reconciled with the data-generation definition before deciding which formula is authoritative.
- The committed training script recomputes `suspicious_words` from the URL before fitting, while the CSV values disagree with the committed extractor in 878 rows. This means the serialized training feature was not necessarily the stored CSV feature.

## 7. Correlation, constant values and suspicious label relationships

No non-target feature is constant across the whole dataset. `suspicious_words` is the closest to near-constant: zero in 97.87% of all rows. It is sparse, but not a constant feature.

Pearson-correlated numeric feature pairs with |r| ≥ 0.70:

| feature_a | feature_b | pearson_r |
| --- | --- | --- |
| url_length | digits_count | 0.8255 |
| has_https | has_ip | -0.7824 |

Spearman associations with the binary label (descriptive only; correlation magnitude can understate deterministic threshold separation under severe imbalance):

| feature | spearman_with_label |
| --- | --- |
| num_subdirs | 0.14045 |
| url_length | 0.12366 |
| num_dots | 0.11707 |
| entropy | 0.11332 |
| digits_count | 0.08831 |
| has_ip | 0.06970 |
| has_https | 0.06285 |
| special_char_count | 0.05408 |
| num_params | 0.02373 |
| suspicious_words | 0.00878 |

Most consequential relationships are conditional distributions, not the global correlation coefficients:

- `num_subdirs` is exactly 0 for all label 0 rows and at least 2 for all label 1 rows. In the committed extractor it is the count of `/` characters, including the two slashes in `http://` or `https://`; it is not literally a count of path subdirectories. This single feature perfectly separates the observed labels.
- `has_https` is 0 for every label 0 row; it is 1 for 43.63% of label 1 rows. `has_ip` is also 0 for every label 0 row and 1 for 48.80% of label 1 rows.
- `tld` missingness is almost deterministic by label, while the stored numeric TLD values correlate with IP-host rows.
- These are strong signs of a collection-source/format shortcut. They do not prove malicious intent, prove all labels are correct, or establish that a feature was generated from the target. The causal explanation remains unverified without the collection pipeline.

## 8. Provenance and likely construction bias

### Verified from repository files

- `model/README.md` documents the 0/1 mapping and asserts that benign samples were sourced from domain rankings and phishing samples from active feeds.
- `model/artifacts/model_metadata.json` records the same mapping and historical benchmark results of 1.0; it also documents the bare-domain/missing-TLD explanation.
- `model/Code/feature_extractor.py` and `model/Code/train.py` define the current feature contract; the training script recomputes `suspicious_words` during training.
- The source CSV and committed artifacts were hash-compared with `HEAD` before analysis and matched exactly (see final verification below).

### Unresolved

- No original dataset citation, upstream download record, collection timestamp, feed snapshot, deduplication log, label adjudication procedure, or generator script was found in the repository.
- The README's source description is project documentation, not independent evidence that the row-level labels or classes have the claimed meanings.
- Extreme repetition in several host/path templates and 77,598 IP-address hostnames is consistent with feed/vendor or bulk-generated URL patterns, but EDA alone cannot establish that data is synthetic.

## 9. Audit of existing EDA

- `model/EDA/eda_analysis.ipynb` previously had only two minimal cells and invalid Python expressions for the CSV path and label indexing; it did not contain executed outputs or interpretations.
- The old TLD chart overplotted bars for classes at the same positions and only visibly represented the final class; it was misleading. It is replaced by side-by-side within-class percentages and explicitly labels the stored field as raw.
- The old report omitted missing TLD values from its top-value listing (so label 0 appeared to have no TLD distribution), included `label` in IQR outlier screening, and made broad target-leakage claims without distinguishing label shortcut from verified causal leakage.
- Its basic shape, missing counts, duplicate counts, class counts and numerical summary values match this read-only audit. The 100% structural separation is confirmed; the generation mechanism causing it is not verified.
- The committed `model/README.md` and metadata assert historical perfect scores. This audit did not execute or independently validate any model; given the perfect structural shortcut, those scores are not evidence of real-world generalization.

## 10. Risks to real-world phishing detection

- A model may learn “bare string means legitimate; URL with a scheme/slashes means phishing” rather than phishing behavior. Valid legitimate URLs with paths/schemes are absent from label 0 in this dataset.
- A model may learn the missing-TLD signal and invalid numeric TLDs from IP addresses.
- The 194:1 imbalance and only 820 label-0 examples create poor coverage of legitimate URL diversity and can make aggregate metrics misleading.
- Repeated hosts, registrable domains and path templates can produce overly optimistic row-random evaluation.
- Stale or unknown collection dates mean temporal drift and label validity cannot be assessed.
- Static lexical features cannot by themselves determine whether a destination currently hosts phishing content; no live URL requests were performed in this audit.

## 11. Findings and recommended disposition

| Severity | Finding | Evidence | Recommendation |
|---|---|---|---|
| **Critical** | Class identity is perfectly confounded with URL input format / slash count. | Label 0: 820/820 scheme-less and `num_subdirs=0`; label 1: 159,244/159,244 HTTP(S), `num_subdirs>=2`. | **Investigate/replace for benchmark use.** Obtain comparable benign full URLs and verify provenance before any model development. Preserve this source unchanged. |
| **Critical** | Original labels and collection process are not independently verifiable. | No upstream citation, dates, annotation method or committed collection script; project docs alone provide the mapping. | **Investigate.** Obtain source, licensing, timestamp and labeling evidence; do not claim verified semantics until then. |
| **High** | TLD is systematically missing or invalid for large portions of data. | 821 missing values, 820 from label 0; 77,600 numeric stored TLDs, mostly IP hosts; 78,448 disagreements with current extractor. | **Repair only in a separately reviewed derived copy.** Recompute from parsed hostname using PSL-aware logic; preserve raw column and provenance. Do not impute silently. |
| **High** | Feature calculations are inconsistent with the committed extractor. | Mismatch counts: special chars 16,139; suspicious words 878; parameters 347; IP flag 109. | **Investigate/repair.** Establish the historical feature definitions; then recompute from raw URLs and retain before/after audits. |
| **High** | Row-wise random splitting is vulnerable to domain/template overlap. | 18,946 repeated registrable-domain groups; 4,918 repeated host/path templates; estimated ~8,761 repeated groups straddle an illustrative 80/20 split. | **Retain grouping keys and use domain-aware splitting** after label/provenance review; group IPs by exact IP and hosted services carefully. |
| **High** | Severe class imbalance and undercoverage of legitimate URLs. | 820 vs 159,244 (194.2:1); label 0 URLs only 6–22 characters and have no path/scheme. | **Investigate/add data.** Do not discard label 0 or balance automatically. Add diverse, independently verified benign full URLs and representative phishing examples. |
| **Medium** | Duplicate/URL-variant groups warrant manual policy. | 93 scheme-preserving normalized collisions; 629 scheme-ignored collisions; no mixed-label normalized collisions found. | **Investigate** exact variants and define conservative normalization before resolving duplicates. |
| **Medium** | Extreme count/length tails and templated content may reflect sources rather than general URL behavior. | URL length max 25,523; 4,918 repeated path templates; highly repeated IP-host paths. | **Investigate source/records**; retain until validated. IQR flags are not grounds for deletion. |
| **Low** | Several features are correlated or sparse. | Pearson: `url_length`–`digits_count` r≈0.83, `has_https`–`has_ip` r≈−0.78; `suspicious_words=0` for 97.87%. | **Retain pending validation**; evaluate redundancy and stability later, on source-verified data. |

### Feature decisions (provisional)

- `url_length`, `num_dots`, `has_https`, `digits_count`, `entropy`: values agree with the committed extractor on this corpus; retain as candidates, subject to reparsing and deployment parity checks.
- `num_subdirs`: name is misleading and value is a slash count; do not use as a literal directory-depth feature. Investigate/redefine only in a future approved feature phase.
- `has_ip`: 109 stored values disagree with current host-IP semantics; investigate whether the old calculation detected any IP substring.
- `num_params`: 347 rows disagree with URL-query semantics; inspect fragment and repeated-question-mark edge cases before deciding.
- `suspicious_words`: 878 values differ from the committed 15-keyword implementation; retain raw URL as source and recompute only in an approved derived dataset.
- `tld`: do not trust as currently stored; repair separately using parsed host + PSL, preserving the original field.
- `special_char_count`: the committed extractor's character set and CSV formula disagree in 16,139 records; resolve whether `=` belongs before recomputing.
- `url`: retain as immutable source and audit key; maintain raw and normalized forms separately. Do not train on the raw URL as a feature without a separately approved design.

## 12. Proposed preprocessing plan — NOT APPLIED

1. **Resolve provenance first:** record the upstream URL/citation, license, collection date/window, source feed/ranking, label meaning, and annotation confidence. Preserve the current file/hash as immutable input.
2. **Maintain raw and normalized URL fields:** trim surrounding whitespace only in a derived column; lowercase/IDNA-normalize host, strip a terminal dot, parse scheme/host/port/path/query/fragment separately, and do not collapse HTTP with HTTPS. Keep original strings unchanged. Reject/flag parse failures rather than silently deleting them.
3. **Domain extraction:** use a pinned, versioned Public Suffix List including PRIVATE rules; retain hostname, IP address, public suffix, registrable domain, and extraction status as separate derived values. Review hosted-service boundaries and public-suffix-only names.
4. **Missing values:** retain explicit missing indicators and investigate why missingness aligns with label. Recompute derived TLD from URL only after confirming the source policy; never fill with a value that acts as a class code without documenting the semantics.
5. **Duplicates and conflicts:** report exact duplicates, conservative normalized duplicates, scheme-insensitive candidates and mixed labels. Do not automatically drop; adjudicate conflicts against source evidence and preserve a duplicate/decision log.
6. **Feature recomputation:** derive all engineered features from raw URLs with one versioned extractor shared by offline analysis and runtime. Reconcile special-character, query-count, IP and keyword definitions first; store both original and recomputed columns during validation.
7. **Data supplementation:** collect independently verified legitimate full URLs with path/query variation and more representative phishing cases, while avoiding collection-source shortcuts. Add source, time, and label-confidence metadata.
8. **Domain-aware evaluation split:** group by PSL registrable domain; group IP-address hosts by exact IP. Keep groups wholly in one partition, assess whether both labels are represented, and report any unassignable or mixed-label groups. Consider temporal holdout only after source dates are available.
9. **Class imbalance (future, not now):** first improve coverage and use group-aware evaluation. Later compare class-weighted/cost-sensitive approaches and carefully scoped resampling only within training folds; never balance before splitting, and do not delete the minority class. Use per-class precision/recall, PR-AUC, calibration and operational false-positive/false-negative costs rather than accuracy alone.

**No preprocessing, cleaning, row removal, imputation, encoding, resampling, split, or predictive-model evaluation was performed in this phase.**

## 13. Final verification

- The source CSV SHA-256 is recorded above. Before analysis, `git hash-object` matched `git rev-parse HEAD:<path>` for the CSV and every tracked model artifact.
- No model artifact was opened for inference or modified. No training script or other training command was executed in this audit.
- This report and its helper/notebook/visualizations are confined to `model/EDA/`.

## Evidence sources

- `model/README.md` (project label mapping, source assertions and historical benchmark description).
- `model/artifacts/model_metadata.json` (project label mapping and historical metadata; not independently validated here).
- `model/Code/train.py` and `model/Code/feature_extractor.py` (current feature and label mapping definitions; scripts inspected but not executed).
- Official Public Suffix List snapshot: `https://publicsuffix.org/list/public_suffix_list.dat`, version `2026-11-11_17-18-20_UTC`, stored at `model/EDA/public_suffix_list.dat` for reproducibility.
