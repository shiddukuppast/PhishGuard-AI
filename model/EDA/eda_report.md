# PhishGuard AI - EDA Report

> **Superseded:** This initial report contains incomplete analysis and several misleading interpretations. See [data_quality_and_bias_report.md](./data_quality_and_bias_report.md) for the audited findings and corrections. This file is retained as a record of the first EDA pass.

Dataset: `model/Data/phishing_features.csv`

## 1) Dataset shape and columns
- Shape: 160064 rows x 13 columns
- Columns: url, label, url_length, num_dots, has_https, has_ip, num_subdirs, num_params, suspicious_words, tld, special_char_count, digits_count, entropy

## 2) Data types
- `url`: str
- `label`: int64
- `url_length`: int64
- `num_dots`: int64
- `has_https`: int64
- `has_ip`: int64
- `num_subdirs`: int64
- `num_params`: int64
- `suspicious_words`: int64
- `tld`: str
- `special_char_count`: int64
- `digits_count`: int64
- `entropy`: float64

## 3) Missing values
- `tld`: 821 missing

## 4) Duplicate rows and duplicate URLs
- Duplicate rows: 0
- Duplicate URLs: 0 duplicates across 160064 unique URLs
- URLs appearing more than once: 0
- URLs with mixed labels across duplicates: 0

## 5) Target label distribution and class imbalance
- Label 0: 820 rows (0.5123%)
- Label 1: 159244 rows (99.4877%)
- Imbalance ratio (majority/minority): 194.20:1

## 6) Feature-wise unique values and distributions
### `url`
- dtype: str
- unique values: 160064
- top values: http://forum.uk.securebankinggroup.com/107519/8af662/475d964a-0243-46bf-aefd-66da26254efa=1, http://b45042.com/fish/29=1, http://bet73018.com/lottery/99=1, https://logiin--metsa-autho.webflow.io/=1, https://mettamasklogiiann.webflow.io/=1, http://bet73018.com/lottery/134=1, https://metamasklogenies.webflow.io/=1, https://mmettamaskilogin.webflow.io/=1

### `label`
- dtype: int64
- unique values: 2
- min: 0.0, max: 1.0, mean: 0.9948770491803278, median: 1.0, std: 0.0713914423194218
- top values: 1=159244, 0=820

### `url_length`
- dtype: int64
- unique values: 521
- min: 6.0, max: 25523.0, mean: 55.107382047181126, median: 37.0, std: 101.78246856194892
- top values: 34=8918, 33=8248, 28=8170, 29=7953, 35=6199, 32=5247, 30=5201, 27=4929

### `num_dots`
- dtype: int64
- unique values: 19
- min: 1.0, max: 59.0, mean: 2.9989629148340664, median: 3.0, std: 1.1192098555167147
- top values: 4=54712, 3=48173, 2=39331, 1=13783, 5=2276, 6=1059, 7=399, 13=115

### `has_https`
- dtype: int64
- unique values: 2
- min: 0.0, max: 1.0, mean: 0.4340888644542183, median: 0.0, std: 0.4956382319343656
- top values: 0=90582, 1=69482

### `has_ip`
- dtype: int64
- unique values: 2
- min: 0.0, max: 1.0, mean: 0.4854745601759296, median: 0.0, std: 0.4997905282863678
- top values: 0=82357, 1=77707

### `num_subdirs`
- dtype: int64
- unique values: 24
- min: 0.0, max: 104.0, mean: 4.12843612554978, median: 3.0, std: 2.090179974957751
- top values: 3=96717, 4=24865, 7=11346, 8=6636, 5=6372, 6=4474, 9=3386, 10=1855

### `num_params`
- dtype: int64
- unique values: 23
- min: 0.0, max: 45.0, mean: 0.22149890043982406, median: 0.0, std: 0.9356075239288376
- top values: 0=144238, 1=7523, 3=4260, 2=1957, 4=1515, 5=135, 10=97, 7=79

### `suspicious_words`
- dtype: int64
- unique values: 4
- min: 0.0, max: 3.0, mean: 0.023809226309476208, median: 0.0, std: 0.16823495381375211
- top values: 0=156650, 1=3025, 2=381, 3=8

### `tld`
- dtype: str
- unique values: 536
- top values: com=32341, ru=15011, 202=3745, 34=3551, 227=3312, de=2782, app=2758, dev=2691

### `special_char_count`
- dtype: int64
- unique values: 74
- min: 0.0, max: 264.0, mean: 1.4954455717712916, median: 0.0, std: 3.6996269944653175
- top values: 0=98693, 1=25591, 2=10441, 4=4709, 3=4089, 6=3649, 7=2657, 8=2329

### `digits_count`
- dtype: int64
- unique values: 180
- min: 0.0, max: 3413.0, mean: 12.73703643542583, median: 12.0, std: 17.420578631558932
- top values: 0=20524, 15=13721, 16=12336, 1=9833, 14=8933, 2=8229, 3=5936, 4=5726

### `entropy`
- dtype: float64
- unique values: 43101
- min: 2.0588138903312014, max: 6.0304217016406865, mean: 4.246100192176027, median: 4.17146526179041, std: 0.47927532916153825
- top values: 3.939470994001287=1094, 4.152391277629866=1034, 4.0559581516151235=924, 4.0614821867207755=855, 3.936260027531527=837, 3.9690016298759927=690, 4.027169118440618=682, 3.8442328987631917=627

## 7) Numerical feature statistics
### `label`
- count=160064, mean=0.9949, std=0.0714, min=0.0, 25%=1.0000, 50%=1.0000, 75%=1.0000, max=1.0

### `url_length`
- count=160064, mean=55.1074, std=101.7825, min=6.0, 25%=30.0000, 50%=37.0000, 75%=65.0000, max=25523.0

### `num_dots`
- count=160064, mean=2.9990, std=1.1192, min=1.0, 25%=2.0000, 50%=3.0000, 75%=4.0000, max=59.0

### `has_https`
- count=160064, mean=0.4341, std=0.4956, min=0.0, 25%=0.0000, 50%=0.0000, 75%=1.0000, max=1.0

### `has_ip`
- count=160064, mean=0.4855, std=0.4998, min=0.0, 25%=0.0000, 50%=0.0000, 75%=1.0000, max=1.0

### `num_subdirs`
- count=160064, mean=4.1284, std=2.0902, min=0.0, 25%=3.0000, 50%=3.0000, 75%=4.0000, max=104.0

### `num_params`
- count=160064, mean=0.2215, std=0.9356, min=0.0, 25%=0.0000, 50%=0.0000, 75%=0.0000, max=45.0

### `suspicious_words`
- count=160064, mean=0.0238, std=0.1682, min=0.0, 25%=0.0000, 50%=0.0000, 75%=0.0000, max=3.0

### `special_char_count`
- count=160064, mean=1.4954, std=3.6996, min=0.0, 25%=0.0000, 50%=0.0000, 75%=1.0000, max=264.0

### `digits_count`
- count=160064, mean=12.7370, std=17.4206, min=0.0, 25%=3.0000, 50%=12.0000, 75%=16.0000, max=3413.0

### `entropy`
- count=160064, mean=4.2461, std=0.4793, min=2.0588138903312014, 25%=3.9077, 50%=4.1715, 75%=4.4849, max=6.0304217016406865

## 8) Outlier analysis (IQR rule, 1.5 * IQR)
- `label`: 820 outliers (0.5123%) | bounds=[1.0, 1.0]
- `url_length`: 12907 outliers (8.0636%) | bounds=[-22.5, 117.5]
- `num_dots`: 331 outliers (0.2068%) | bounds=[-1.0, 7.0]
- `has_https`: 0 outliers (0.0%) | bounds=[-1.5, 2.5]
- `has_ip`: 0 outliers (0.0%) | bounds=[-1.5, 2.5]
- `num_subdirs`: 30597 outliers (19.1155%) | bounds=[1.5, 5.5]
- `num_params`: 15826 outliers (9.8873%) | bounds=[0.0, 0.0]
- `suspicious_words`: 3414 outliers (2.1329%) | bounds=[0.0, 0.0]
- `special_char_count`: 25339 outliers (15.8305%) | bounds=[-1.5, 2.5]
- `digits_count`: 7199 outliers (4.4976%) | bounds=[-16.5, 35.5]
- `entropy`: 6375 outliers (3.9828%) | bounds=[3.042060477869172, 5.350523925531342]

## 9) URL patterns across phishing and legitimate classes
### Label 0
- rows=820
- https_pct=0.0%, ip_pct=0.0%, avg_url_length=14.08, avg_num_dots=1.035, avg_subdirs=0.0, avg_params=0.0, avg_suspicious_words=0.004, avg_entropy=3.355
- top_tlds: 

### Label 1
- rows=159244
- https_pct=43.63%, ip_pct=48.8%, avg_url_length=55.32, avg_num_dots=3.009, avg_subdirs=4.15, avg_params=0.223, avg_suspicious_words=0.024, avg_entropy=4.251
- top_tlds: com=32341, ru=15011, 202=3745, 34=3551, 227=3312, de=2782, app=2758, dev=2691

## 10) Potential target leakage
- The dataset contains a strong class imbalance and several features are highly signal-rich; some structural features may be near-deterministic proxies for the label.
- `has_https`, `has_ip`, `num_subdirs`, `suspicious_words`, and `tld` are likely to be strongly associated with the target if the dataset construction encoded URL structure into the label.
- If benign and phishing examples were created from different URL templates, the model could learn dataset-generation artifacts rather than generalizable phishing behavior.
- Check whether the URL generation process creates distinct domain families, path schemas, or TLD patterns that are almost unique to one class.

## 11) Leakage risks from duplicate URLs/domains
- Duplicate URLs across rows: 0
- Duplicate URL values with mixed labels: 0
- Domains appearing with more than one label: 31
- If duplicate URLs or identical domains appear in both train and test splits, the evaluation can be over-optimistic or misleading.
- Even without exact URL duplication, repeated domains or hostnames shared across labels can leak identity information into both splits.
- A robust split should group by domain or hostname and ensure no repeated domains cross train/test partitions.

## 12) Immediate concerns requiring investigation
- Confirm whether the dataset was generated from class-specific templates rather than real-world URL variation.
- Review whether `tld`, `has_ip`, `num_subdirs`, and `suspicious_words` are too strongly correlated with the label to be safe for generalization.
- Inspect duplicate URLs and domain-label mixing to assess split leakage risk before any train/test work.
- Review the URL construction logic to determine whether bare domains, custom TLDs, and URL path patterns leak class identity.