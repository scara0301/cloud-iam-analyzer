# Python code walkthrough (line by line)

Covers `app.py`, `iam_analyzer/*.py` and `tests/*.py`. Line numbers match the files as committed.
The DevOps files (Dockerfile, CI, Kubernetes) are in `WALKTHROUGH-devops.md`.

## 0. Vocabulary used throughout

| Term | Meaning |
|---|---|
| **DataFrame** | pandas' table type: named columns, numbered rows |
| **Series** | one column of a DataFrame (a labelled list) |
| **index** | the row labels of a DataFrame/Series; operations line up values by index |
| **NaN / None / NaT** | "missing value" in pandas (NaT is the missing-time version) |
| **boolean mask** | a Series of True/False used to pick rows: `df[mask]` keeps rows where mask is True |
| **docstring** | a string as the first statement of a module/function; documentation, not logic |
| **type hint** | `x: int` or `-> str`: labels for humans and tools, not enforced at runtime |
| **f-string** | `f"text {value}"`: Python substitutes `value` into the text |
| **comprehension** | `[expr for x in items if cond]`: builds a list in one line |
| **decorator** | `@something` above a function: wraps the function to add behaviour |
| **frozenset** | a set that cannot change; very fast "is X in this group?" checks |
| **dataclass** | a class whose fields are declared as annotations; Python writes `__init__` for you |
| **IsolationForest** | an unsupervised model that isolates points with random splits; points isolated in few splits are "anomalies" |
| **contamination** | the fraction of data the forest should call anomalous |
| **ISO-3** | 3-letter country codes (USA, GBR, RUS) used by the world map |

Python syntax reminders: `a if cond else b` is a one-line if; `x[:2]` slices the first two items;
`*` and `**` unpack; `_name` marks a helper meant for internal use; `with ... :` runs a block that
sets something up and cleans it up afterwards.

---

## 1. `app.py`: the Streamlit page (120 lines)

Streamlit re-runs this whole file from top to bottom every time the user interacts with a widget.
Everything below is therefore a *script*, not a long-lived program.

### Imports and setup (lines 1-18)
- **L1** `"""Streamlit entrypoint: ..."""`: module docstring. Documentation only.
- **L3** `from __future__ import annotations`: makes type hints lazy text, so modern hint syntax such as `list[dict]` or `str | None` is safe and hints cost nothing at runtime.
- **L5** `import json`: standard library, used to build and parse JSON text.
- **L7** `import pandas as pd`: pandas under the short name `pd`. Used here only in the type hints on lines 22 and 27.
- **L8** `import streamlit as st`: the web framework, short name `st`. Every `st.something` draws UI.
- **L10** imports `detect_anomalies` (the model) from `iam_analyzer/anomaly.py`.
- **L11** imports `load_settings` (reads environment variables).
- **L12** imports `analyze_policies` (find over-privileged roles) and `role_risk_summary` (rank roles).
- **L13** imports `LogFormatError` (the custom "bad file" error) and `load_events` (the log parser).
- **L14** imports `generate_cloudtrail` and `sample_policies`: the built-in fake data.
- **L15** imports the three chart builders from `viz.py`.
- **L17** `settings = load_settings()`: runs once per script run; returns a `Settings` object holding title, default anomaly rate, sample seed and row cap.
- **L18** `st.set_page_config(...)`: sets the browser-tab title (`page_title`), the tab icon (`page_icon`, a shield emoji) and `layout="wide"` to use the full browser width. Streamlit requires this to run before other `st.` drawing calls.

### Cached helpers (lines 21-28)
- **L21** `@st.cache_data(show_spinner=False)`: decorator. Streamlit remembers this function's return value keyed by its arguments, so calling it again with the same `seed` skips the work. `show_spinner=False` hides the "Running..." indicator.
- **L22** `def _sample_events(seed: int) -> pd.DataFrame:` defines the helper. Leading underscore = internal. It takes an integer and returns a DataFrame.
- **L23** `return load_events(json.dumps(generate_cloudtrail(seed)), "sample.json")`: generate the synthetic CloudTrail dict, turn it into JSON text with `json.dumps`, then parse that text with the same `load_events` that handles uploads. The filename `"sample.json"` matters only because `load_events` checks whether it ends in `.csv`. Doing the JSON round trip means the sample exercises the real upload code path.
- **L26** `@st.cache_data(show_spinner="Scoring events…")`: same decorator but shows the given text as a spinner while the model runs.
- **L27** `def _score(events: pd.DataFrame, contamination: float) -> pd.DataFrame:`: cached on the *contents* of `events` plus the slider value.
- **L28** `return detect_anomalies(events, contamination=contamination)`: run the forest and return events plus `anomaly_score`, `is_anomaly`, `reasons`.

### Header (lines 31-35)
- **L31** `st.title(f"🛡️ {settings.app_title}")`: big page heading. The `f` prefix substitutes the title from settings.
- **L32-35** `st.caption("..." "...")`: small grey text. Two string literals side by side are joined into one by Python (implicit concatenation), which keeps lines short.

### Sidebar inputs (lines 37-50)
- **L37** `with st.sidebar:`: everything indented below is drawn in the left sidebar.
- **L38** `st.header("Data")`: section heading.
- **L39** `logs = st.file_uploader("Audit logs (JSON / NDJSON / CSV)", type=["json", "csv"])`: an upload box. Returns `None` until a file is chosen, then an `UploadedFile`. `type=[...]` restricts the file extensions (NDJSON files are named `.json`).
- **L40** a second upload box for IAM policies, JSON only; stored in `policies_file`.
- **L41** a caption telling users that leaving both empty uses sample data.
- **L42** `st.header("Detection")`.
- **L43-50** `contamination = st.slider(...)`: a slider returning a number. Arguments: label text; `min_value=0.005` (0.5%); `max_value=0.20` (20%); `value=float(settings.default_contamination)` starting position (from the ConfigMap, default 0.03); `step=0.005`; `help=` text shown in a tooltip.

### Reading input (lines 52-69)
- **L52** `try:`: start of error handling for everything that reads user input.
- **L53** `if logs is not None:`: the user uploaded a log file.
- **L54** `events = load_events(logs.getvalue(), logs.name)`: `getvalue()` returns the file's raw bytes; `name` is the filename. Returns the normalised DataFrame.
- **L55** `source_label = logs.name`: remembered for the caption on line 83.
- **L56-58** `else:` use the cached synthetic data and label it "synthetic sample".
- **L59-61** `if events.empty:` the file parsed but contained no usable rows: `st.warning(...)` shows a yellow box and `st.stop()` ends this script run so nothing below executes. `st.stop()` works by raising an internal exception; that is why the `except` on line 67 names specific error types instead of catching everything.
- **L62-64** if there are more rows than `settings.max_rows`, warn (`{:,}` formats numbers with thousands separators) and keep only the first `max_rows` with `events.head(...)`. This protects the model and browser from huge files.
- **L66** `policy_doc = json.loads(policies_file.getvalue()) if policies_file else sample_policies()`: a one-line if. With an uploaded policy file, parse it (`json.loads` accepts bytes); otherwise use the built-in sample roles. An `UploadedFile` counts as true, `None` as false.
- **L67** `except (LogFormatError, json.JSONDecodeError) as exc:`: catches our parser's complaint or invalid policy JSON; `exc` holds the error object.
- **L68** `st.error(f"Could not read input: {exc}")`: red error box with the message.
- **L69** `st.stop()`: do not continue.

### Computing results (lines 71-73)
- **L71** `scored = _score(events, contamination)`: run (or fetch from cache) the model.
- **L72** `anomalies = scored[scored["is_anomaly"]]`: keep only rows where the True/False column `is_anomaly` is True.
- **L73** `findings, hierarchy = analyze_policies(policy_doc)`: returns two DataFrames, unpacked into two variables: `findings` (problems found) and `hierarchy` (one row per permission, for the sunburst).

### Metric tiles (lines 75-83)
- **L75** `c1, c2, c3, c4 = st.columns(4)`: four equal side-by-side containers, unpacked into four names.
- **L76** `c1.metric("Events analysed", f"{len(scored):,}")`: a big-number tile. `len(scored)` is the row count.
- **L77** tile of how many events were flagged.
- **L78** `anomalies["user"].nunique()`: number of distinct users among flagged events.
- **L79-82** tile of critical/high IAM findings: `findings["severity"].isin(["critical","high"])` gives True/False per row, `.sum()` counts the Trues, `int(...)` makes it a plain integer. The `if len(findings) else 0` guards the empty case.
- **L83** caption: `', '.join(scored['provider'].unique())` lists each cloud provider present (e.g. `aws`).

### Tabs (lines 85-120)
- **L85** `tab_activity, tab_iam = st.tabs([...])`: two tabs; the returned containers are unpacked.
- **L87** `with tab_activity:` draws the indented content inside the first tab.
- **L88** `left, right = st.columns(2)`: two equal columns.
- **L89** `left.plotly_chart(anomaly_geo_map(scored), use_container_width=True)`: draw the world map; `use_container_width=True` stretches it to fill the column (newer Streamlit versions may print a deprecation warning suggesting `width="stretch"`).
- **L90** same for the timeline in the right column.
- **L91** `st.subheader("Flagged events")`.
- **L92-107** `st.dataframe(...)` draws an interactive table. The first argument reads inside-out: `anomalies.sort_values("anomaly_score", ascending=False)` sorts most suspicious first; `[[...]]` (double brackets) selects a list of columns (lines 94-103) in a chosen order; `hide_index=True` hides pandas' row numbers.
- **L109** `with tab_iam:` the second tab.
- **L110** draw the sunburst chart.
- **L111** `left, right = st.columns([2, 1])`: unequal columns, widths 2:1.
- **L112-117** `with left:` shows "Findings": if `findings.empty` a green `st.success` box, otherwise the table.
- **L118-120** `with right:` shows "Role risk", the ranking from `role_risk_summary`.

---

## 2. `iam_analyzer/__init__.py`
- **L1** docstring; makes the folder a Python package.
- **L3** `__version__ = "1.0.0"`: a conventional version string.

---

## 3. `iam_analyzer/config.py`: settings (33 lines)

- **L1-4** docstring explaining values arrive from environment variables (from the Kubernetes ConfigMap in the cluster).
- **L6** future annotations import (see section 1, L3).
- **L8** `import os`: gives access to environment variables (`os.environ`).
- **L9** `from dataclasses import dataclass`: the decorator used on line 19.
- **L12** `def _float_env(name: str, default: float) -> float:`: read an environment variable as a number.
- **L13** `try:` attempt the conversion.
- **L14** `return float(os.environ.get(name, default))`: `os.environ.get(name, default)` returns the variable's text, or `default` if unset; `float(...)` converts it.
- **L15-16** `except ValueError: return default`: if the text is not a number (e.g. `"abc"`), fall back to the default instead of crashing.
- **L19** `@dataclass(frozen=True)`: auto-generates the constructor; `frozen=True` makes instances read-only after creation.
- **L20** `class Settings:` the container.
- **L21-24** four fields with types: `app_title` (text), `default_contamination` (decimal), `sample_seed` (integer), `max_rows` (integer).
- **L27** `def load_settings() -> Settings:`.
- **L28** `return Settings(` ... builds and returns the object.
- **L29** `app_title=os.environ.get("APP_TITLE", "Cloud Security Posture & IAM Analyzer")`: environment value or the default title.
- **L30** `default_contamination=min(max(_float_env("DEFAULT_CONTAMINATION", 0.03), 0.001), 0.5)`: read the number (default 0.03), `max(..., 0.001)` raises anything below 0.001 up to 0.001, `min(..., 0.5)` lowers anything above 0.5 to 0.5. Net effect: clamp into [0.001, 0.5], the range IsolationForest accepts.
- **L31** `sample_seed=int(_float_env("SAMPLE_SEED", 42))`: read as a float first (so `"42"` or `"42.0"` both work) then convert to an integer.
- **L32** `max_rows=int(_float_env("MAX_ROWS", 200_000))`: row cap; `200_000` is just 200000 with a readability underscore.

---

## 4. `iam_analyzer/loaders.py`: turning logs into one table (161 lines)

### Header and constants (1-31)
- **L1-8** docstring: three providers mapped to one schema; the map needs an extra `country_iso3` column because logs contain no geolocation; missing = `UNK`.
- **L10** future annotations.
- **L12** `import io`: used for `io.StringIO`, which lets pandas read text as if it were a file.
- **L13** `import json`.
- **L14** `from typing import Any, Iterable`: type-hint helpers (`Any` = anything, `Iterable` = anything you can loop over).
- **L16** `import pandas as pd`.
- **L18-29** `COLUMNS = [...]`: the one schema every provider is converted to. Order here is the column order of the output: `event_time`, `provider`, `event_name`, `event_source`, `user`, `source_ip`, `region`, `user_agent`, `error_code`, `country_iso3`.
- **L31** `UNKNOWN_COUNTRY = "UNK"`: the placeholder for "no country info". `viz.py` imports this.

### Custom error (34-35)
- **L34** `class LogFormatError(ValueError):`: a new error type that *is a* `ValueError`. Naming it lets `app.py` catch exactly "bad input" and nothing else.
- **L35** docstring is the whole body (a class needs at least one statement; a docstring counts).

### `_records_from_json` (38-57): get a list of event dicts out of JSON text
- **L38** signature: takes text, returns a list of dictionaries.
- **L39** `text = text.strip()` removes leading/trailing whitespace and newlines.
- **L40-41** empty text returns an empty list.
- **L42-43** `try: data = json.loads(text)`: attempt to parse the whole text as one JSON document.
- **L44** `except json.JSONDecodeError:` it was not one valid JSON document.
- **L45** comment: it may be NDJSON, one JSON object per line (what GCP log exports and CloudTrail Lake produce).
- **L46-47** inner `try`: `[json.loads(line) for line in text.splitlines() if line.strip()]` parses each non-blank line separately into a list.
- **L48-49** if that also fails, `raise LogFormatError(f"Invalid JSON: {exc}") from exc`: raise our error, with `from exc` keeping the original error attached for debugging.
- **L50** `if isinstance(data, dict):` the JSON root is an object.
- **L51** loop over the wrapper-key names providers use: `Records` (AWS CloudTrail), `value` (Azure), `entries` (GCP), `events`, `items`.
- **L52-53** `if isinstance(data.get(key), list): return data[key]`: if that key exists and holds a list, return the list.
- **L54** no wrapper key: treat the object itself as a single event, `[data]`.
- **L55-56** the root is already a list of events: return it.
- **L57** anything else (a bare number or string) raises `LogFormatError`.

### `_first` (60-67): coalesce several candidate columns into one
- **L60** takes a DataFrame and a list of column names to try, in priority order.
- **L61** docstring: "the first non-empty value across candidate columns" (SQL calls this COALESCE).
- **L62** `result = pd.Series([None] * len(df), index=df.index, dtype="object")`: start with a column of all-missing values, one per row, same row labels as `df`.
- **L63** loop over each candidate name in order.
- **L64** `if name in df.columns:` skip names that do not exist in this file.
- **L65** `col = df[name].replace("", None)`: treat empty-string cells as missing.
- **L66** `result = result.where(result.notna(), col)`: `where(condition, other)` keeps the existing value where the condition is true and takes `other` where false. So: keep what we already found; fill the remaining gaps from this candidate. Earlier candidates win.
- **L67** return the combined column.

### `_detect_provider` (70-80): which cloud is this?
- **L70** takes the set of (lowercased) column names.
- **L71-72** `if {"eventname","eventsource"} <= columns: return "aws"`: `<=` on sets means "is a subset of": both CloudTrail field names are present.
- **L73-74** a GCP-only field `protopayload.methodname` means `"gcp"`.
- **L75-76** `operationname` (or nested `operationname.value`) means `"azure"`.
- **L77-80** none matched: `raise LogFormatError(...)` with a friendly message (two string literals joined).

### `normalize_events` (83-148): the core mapper
- **L83-84** takes the raw flattened DataFrame; docstring.
- **L85-86** `if raw.empty: return pd.DataFrame(columns=COLUMNS)`: an empty input returns an empty table that still has the right columns.
- **L88** `df = raw.copy()`: work on a copy so the caller's data is never modified.
- **L89** `df.columns = [str(c).lower() for c in df.columns]`: lowercase every column name, so `eventTime`, `EventTime` and `eventtime` all match the lowercase candidates used below.
- **L90** `provider = _detect_provider(set(df.columns))`.
- **L92** `out = pd.DataFrame(index=df.index)`: an empty result table with the same row labels.
- **L93** `out["provider"] = provider`: one value broadcast to all rows.
- **L95-112** AWS branch (each line fills one output column using `_first` with candidate names):
  - **L96** `event_time` from `eventtime` or `event_time`.
  - **L97** `event_name` from `eventname`. **L98** `event_source` from `eventsource`.
  - **L99-108** `user`: try `useridentity.arn` first (the dotted names exist because `json_normalize` flattens nested JSON: `{"userIdentity": {"arn": ...}}` becomes `userIdentity.arn`), then user name, principal id, and flat-CSV fallbacks `username` and `arn`.
  - **L109** `source_ip` from `sourceipaddress`. **L110** `region` from `awsregion`. **L111** `user_agent` from `useragent`. **L112** `error_code` from `errorcode`.
- **L113-124** Azure branch:
  - **L114** time from `eventtimestamp`, `time` or `submissiontimestamp`.
  - **L115** event name from the nested `operationname.value` or the plain `operationname`.
  - **L116-118** source = the resource provider name.
  - **L119** `user` = `caller` (or a claim). **L120** IP = `calleripaddress`. **L121** region = `location`.
  - **L122** `out["user_agent"] = None`: Azure activity logs carry none.
  - **L123** `status = _first(df, ["status.value", "status"])`.
  - **L124** `out["error_code"] = status.where(status.astype(str).str.lower() == "failed", None)`: keep the status text only when it equals "failed" (case-insensitive); everything else becomes missing. So only failures count as errors.
- **L125-134** `else:  # gcp` branch:
  - **L126-132** time, method name, service name, principal email, caller IP, location/region, caller user-agent, from the `protopayload.*` flattened names.
  - **L133** `code = pd.to_numeric(_first(df, ["protopayload.status.code"]), errors="coerce")`: convert the status code to numbers; unparseable becomes NaN (`errors="coerce"`).
  - **L134** `out["error_code"] = code.where(code.fillna(0) != 0, None).astype("object")`: keep the code only when it is non-zero (zero = OK in Google's status model); `astype("object")` lets the column hold numbers and missing values together.
- **L136** `country_iso3` from `country_iso3`, `geo.country_iso3` or `country`: the optional enrichment column.
- **L138** `out["event_time"] = pd.to_datetime(out["event_time"], utc=True, errors="coerce")`: convert text to real timestamps in UTC; bad values become NaT.
- **L139** `out = out.dropna(subset=["event_time", "event_name"])`: drop rows missing a timestamp or event name; they cannot be analysed.
- **L140-144** `fillna("unknown")` on `user`, `source_ip`, `region`, `user_agent`, `event_source`: no missing text values downstream.
- **L145** `country_iso3`: missing becomes `"UNK"`, `.astype(str)` forces text, `.str.upper()` upper-cases (`usa` becomes `USA`).
- **L146** `out["error_code"] = out["error_code"].where(out["error_code"].notna(), None)`: tidies missing values (NaN) to `None`.
- **L148** `return out[COLUMNS].sort_values("event_time").reset_index(drop=True)`: select columns in the standard order, sort oldest to newest, renumber rows from 0 (`drop=True` discards the old numbers).

### `load_events` (151-161): the public entry point
- **L151** takes `content` (raw bytes or text; `bytes | str` means "either") and a filename.
- **L153** `text = content.decode("utf-8-sig") if isinstance(content, bytes) else content`: if bytes, decode to text; `utf-8-sig` also strips the invisible BOM that Excel adds. Otherwise it is already text.
- **L154** `if filename.lower().endswith(".csv"):` file type by extension.
- **L155-158** read the CSV: `pd.read_csv(io.StringIO(text), dtype=str)`; `StringIO` wraps text as a file-like object and `dtype=str` keeps every cell as text (no surprise number conversions). Parser/empty errors are re-raised as `LogFormatError`.
- **L159-160** otherwise JSON: `pd.json_normalize(_records_from_json(text))` flattens nested dictionaries into dotted column names.
- **L161** `return normalize_events(raw)`.

---

## 5. `iam_analyzer/anomaly.py`: the model (131 lines)

### Header and constants
- **L1-6** docstring: features describe how unusual a call is globally and for its caller; a rule layer adds readable reasons.
- **L10** `import numpy as np` (math on arrays). **L11** pandas. **L12** `from sklearn.ensemble import IsolationForest`.
- **L14-39** `SENSITIVE_EVENTS = frozenset({...})`: API names that matter for security: creating users/keys/login profiles, attaching or writing IAM policies, changing trust policies, tampering with CloudTrail (`DeleteTrail`, `StopLogging`, `UpdateTrail`, `PutEventSelectors`), changing bucket policies, disabling/deleting KMS keys, deleting flow logs, reading secrets (`GetSecretValue`).
- **L41-52** `FEATURES = [...]`: the ten feature columns fed to the model, in a fixed order: time of day as `hour_sin`/`hour_cos`; four rarity scores; and flags `is_error`, `is_sensitive`, `is_login`, plus `user_burst`.

### `_rarity` (55-62)
- **L55** takes the DataFrame and a list of column names (`keys`).
- **L57** `counts = df.groupby(keys)["event_name"].transform("size")`: group rows by the key columns; `transform("size")` gives *every row* the size of its own group (so the result has one number per row, unlike a normal groupby that shrinks).
- **L58-59** one key (e.g. just `event_name`): the total is all rows, `len(df)`.
- **L60-61** several keys (e.g. `user`, `event_name`): the total is the size of the group defined by all keys *except the last* (`keys[:-1]` = the user). So the share is "of this user's events, what fraction is this event".
- **L62** `return -np.log(counts / total)`: `counts/total` is the share (0 to 1). `-log(share)` turns it into a rarity: share 1 gives 0, share 0.1 gives about 2.3, share 0.01 gives about 4.6. Bigger means rarer.

### `build_features` (65-83): one row of numbers per event
- **L67** `ts = events["event_time"]`.
- **L68** `hour = ts.dt.hour + ts.dt.minute / 60.0`: time of day as a decimal (14:30 becomes 14.5); `.dt` accesses datetime parts.
- **L69** `feats = pd.DataFrame(index=events.index)`: empty table, same rows.
- **L70-71** `hour_sin` / `hour_cos`: `sin(2π·hour/24)` and `cos(...)` place the hour on a circle so 23:59 and 00:01 are close together, which a plain 0-24 number would not do. Two columns are needed to identify a point on a circle.
- **L72** `event_rarity`: how rare this API call is across everyone.
- **L73** `user_event_rarity`: how rare it is for this user.
- **L74** `user_country_rarity`: how rare this country is for this user.
- **L75** `user_ip_rarity`: how rare this source IP is for this user.
- **L76** `is_error`: `error_code.notna()` is True where an error exists; `.astype(float)` turns True/False into 1.0/0.0.
- **L77** `is_sensitive`: `isin(SENSITIVE_EVENTS)` True for names in the set; as 1.0/0.0.
- **L78** `is_login`: `eq("ConsoleLogin")` equals check; 1.0/0.0.
- **L80** comment about bursts.
- **L81** `bucket = ts.dt.floor("5min")`: round every timestamp down to its 5-minute window (10:07 becomes 10:05).
- **L82** `user_burst`: group by (user, window), `transform("size")` gives each row the number of events by that user in that window; `np.log1p` is `log(1+x)`, which compresses large counts and stays defined at 0.
- **L83** return the feature table.

### `_reasons` (86-102): human-readable explanations
- **L87** `hour = events["event_time"].dt.hour`.
- **L88-89** `minor_share = -np.log(0.10)` (about 2.30): the rarity of a 10% share. Rarity above this means the user does under 10% of their activity that way.
- **L90-98** `rules = {...}`: a dictionary mapping a label to a True/False Series (a mask):
  - "sensitive IAM/logging action": `is_sensitive > 0`.
  - "unusual country for user": country rarity above `minor_share`.
  - "unusual source IP for user": IP rarity above `minor_share`.
  - "rare action for user": user-event rarity above 4.0 (under about 1.8% share).
  - "off-hours activity": `(hour < 6) | (hour >= 22)`: `|` is element-wise "or" on Series; the parentheses are required.
  - "denied / failed call": `is_error > 0`.
  - "burst of API calls": `user_burst > np.log1p(8)`, i.e. more than 8 events in a 5-minute window.
- **L99** `reasons = pd.Series("", index=events.index, dtype="object")`: start every row with an empty string.
- **L100-101** `for label, mask in rules.items(): reasons = reasons.where(~mask, reasons + label + "; ")`: `~mask` is "not mask". `where` keeps the old text where the rule did NOT fire and substitutes old text plus `label; ` where it did. Looping accumulates every rule that fires.
- **L102** `return reasons.str.rstrip("; ")`: remove trailing `;` and space characters. (`rstrip` removes any of the listed characters, not the literal two-character string.)

### `detect_anomalies` (105-131): the public function
- **L105-109** parameters: the events, `contamination=0.03` (flag about 3%) and `random_state=42` (makes results repeatable).
- **L110** docstring: returns events plus three new columns.
- **L111** `result = events.copy().reset_index(drop=True)`: copy and renumber 0..n-1 so positions line up.
- **L112-116** `if len(result) < 10:` too little data to learn from: add `anomaly_score = 0.0`, `is_anomaly = False`, `reasons = ""` and return early.
- **L118** `feats = build_features(result)`.
- **L119-124** `IsolationForest(n_estimators=200, contamination=contamination, random_state=random_state, n_jobs=1)`: 200 random trees; the contamination fraction decides the cut-off; fixed random seed; one CPU thread (avoids oversubscribing a small container).
- **L125** `model.fit(feats[FEATURES])`: train on the ten feature columns in fixed order. It is unsupervised: no labels.
- **L126** `raw = -model.score_samples(feats[FEATURES])`: scikit-learn returns lower = more abnormal; the minus sign flips it so higher = more abnormal.
- **L127** `span = raw.max() - raw.min()`: the range of scores.
- **L128** `result["anomaly_score"] = (raw - raw.min()) / span if span else 0.0`: min-max scale to 0..1; if every score is identical, `span` is 0, which Python treats as false, so 0.0 is used instead of dividing by zero.
- **L129** `result["is_anomaly"] = model.predict(feats[FEATURES]) == -1`: `predict` returns -1 for outliers and 1 for normal points; comparing to -1 gives True/False.
- **L130** attach the reasons. **L131** return.

---

## 6. `iam_analyzer/iam.py`: policy analysis (185 lines)

### Header and constants (1-46)
- **L1-7** docstring including the expected input shape: a `roles` list; each role has a `name`, a `trust_policy` and `policies` (each with a `name` and `document` containing `Statement`s).
- **L11** `from typing import Any`. **L13** pandas.
- **L15** `HIGH_IMPACT_SERVICES`: services whose wildcards are dangerous: `iam`, `sts`, `kms`, `organizations`, `cloudtrail`.
- **L16-29** `PRIVESC_ACTIONS`: lowercase action names that let an identity gain more power (pass a role, create keys, attach/put policies, change trust, change policy versions, assume role).
- **L31** `READ_ONLY_PREFIXES = ("Get", "List", "Describe", "Lookup")`: an action name starting with one of these only reads data. A tuple, because `str.startswith` accepts a tuple.
- **L33** `RISK_LABELS = {0:"none", 1:"low", 2:"medium", 3:"high", 4:"admin"}`: score to word.
- **L35** `FINDING_COLUMNS` and **L36-46** `HIERARCHY_COLUMNS`: fixed column lists for the two output tables, so empty results keep the right shape.

### Helpers (49-80)
- **L49-52** `_as_list(value)`: AWS lets a field be either a single value or a list. `None` becomes `[]`; a list stays; a lone value is wrapped as `[value]`. This lets later code always loop.
- **L55-59** `_split_action(action)`: split `"s3:GetObject"` into `("s3", "GetObject")`.
  - **L56-57** the special action `"*"` returns `("*", "*")`.
  - **L58** `action.partition(":")` splits at the first colon into (before, separator, after); `_` discards the separator.
  - **L59** returns the lowercase service and the name, using `"*"` if there was no name (`name or "*"`).
- **L62-80** `_action_risk(action, resources)` returns 0-4. Checks run top to bottom; the first that matches wins:
  - **L63** split the action. **L64** `all_resources = "*" in resources` (the policy applies to every resource).
  - **L65-66** service `*` and all resources: score 4 (full admin).
  - **L67-68** service `*` but limited resources: 3.
  - **L69** `wildcard = "*" in name` (e.g. `Get*`, `*`).
  - **L70-71** name starts with a read-only prefix: 1 if there is a wildcard or all resources, else 0. This was added so `iam:Get*` on `*` is "low", not "medium".
  - **L72-73** a privilege-escalation action on all resources: 3.
  - **L74-75** wildcard on a high-impact service on all resources (e.g. `iam:*` on `*`): 3.
  - **L76-77** wildcard plus all resources on any other service (e.g. `sagemaker:*`): 2.
  - **L78-80** *(redundant code)* both the `if` on L78 and the final `return 1` on L80 return 1, so the `if` does nothing. It can be deleted without changing behaviour.

### `analyze_policies` (83-171)
- **L83** takes the policy document; returns a pair of DataFrames.
- **L85-86** two empty lists to collect `findings` (problems) and `rows` (every permission).
- **L88** `for role in doc.get("roles", []):` loop over roles; `.get` with a default avoids errors on a missing key.
- **L89** role name, default `"unnamed-role"`.
- **L91** loop over trust-policy statements: `role.get("trust_policy", {}).get("Statement")` wrapped by `_as_list`.
- **L92** `principals = stmt.get("Principal", {})`: who may assume the role.
- **L93** `aws = _as_list(principals.get("AWS") if isinstance(principals, dict) else principals)`: `Principal` can be a dict like `{"AWS": ...}` or a bare string `"*"`; this normalises both into a list.
- **L94** `if stmt.get("Effect") == "Allow" and "*" in aws and "Condition" not in stmt:` an Allow statement open to every principal and with no restricting condition.
- **L95-103** append a `critical` finding "Role assumable by any principal".
- **L105** loop over the role's policies. **L106** policy name.
- **L107** loop over the policy's statements.
- **L108** `effect = stmt.get("Effect", "Allow")`.
- **L109** `resources = [str(r) for r in _as_list(stmt.get("Resource"))] or ["*"]`: list of resource strings; `or ["*"]` means a statement with no Resource is treated conservatively as all resources.
- **L110** list of action strings.
- **L112-121** if the statement uses `NotAction` with Allow (allow everything *except* these): `high` finding.
- **L123** loop over each action.
- **L124** split into service and name.
- **L125** `risk = _action_risk(action, resources) if effect == "Allow" else 0`: Deny statements are never risky.
- **L126-138** append a row: role, policy, service (`"ALL"` for `*`), action name, effect, resources joined with commas, numeric risk, risk word, `count: 1`. These rows feed the sunburst.
- **L139-140** `if effect != "Allow" or risk < 2: continue`: no finding for Deny or low-risk actions; `continue` jumps to the next action.
- **L141-143** risk 4: "Full administrator access", `critical`.
- **L144-146** a privilege-escalation action: `high`.
- **L147-149** service in the high-impact set: "Wildcard on <service>", `high`.
- **L150-152** everything else: "Wildcard action and resource", `medium`.
  - *Known imprecision:* a statement with `Action "*"` and limited resources scores 3 but falls into this `else` branch and is labelled medium.
- **L153-161** append the finding.
- **L163** `order = {"critical": 0, ...}`: sort ranking.
- **L164** build the findings DataFrame with fixed columns.
- **L165-170** if not empty: `drop_duplicates()` removes repeats, `sort_values("severity", key=lambda s: s.map(order))` sorts by the ranking (the `key` function converts words to numbers; `lambda` is a tiny unnamed function), `reset_index(drop=True)` renumbers.
- **L171** return `findings_df` and the rows as a DataFrame.

### `role_risk_summary` (174-185)
- **L176-177** nothing to summarise: empty frame with the right columns.
- **L178-183** `groupby("role").agg(max_risk=("risk_score","max"), permissions=("count","sum"))` gives per role the highest risk score and the number of permissions; `.reset_index()` turns the role from an index back into a column; `.sort_values([...], ascending=False)` ranks highest risk first, ties broken by more permissions.
- **L184** `summary["max_risk"].map(RISK_LABELS)` turns numbers into words.
- **L185** renumber and return.

---

## 7. `iam_analyzer/viz.py`: charts (78 lines)

- **L5-7** imports: pandas; `plotly.express as px` (quick high-level charts); `plotly.graph_objects as go` (low-level figure objects).
- **L9** `from .loaders import UNKNOWN_COUNTRY`: the leading dot means "from this same package".
- **L12-18** `_empty(message)`: a blank figure showing text.
  - **L13** `go.Figure()` empty figure. **L14** `add_annotation(text=message, showarrow=False, font={"size": 16})` adds centred text with no arrow. **L15-16** hide both axes. **L17** fixed height 360 and zero side margins. **L18** return.
- **L21-42** `anomaly_geo_map(events)`:
  - **L23** `flagged = events[events["is_anomaly"] & (events["country_iso3"] != UNKNOWN_COUNTRY)]`: rows that are anomalies *and* have a known country; `&` is element-wise "and".
  - **L24-25** none: return the "no anomalous events" message figure.
  - **L26-30** group flagged rows by country, `anomalies` = row count, `users` = distinct users, `.reset_index()`.
  - **L31-39** `px.choropleth(...)`: `locations` = the country column, `locationmode="ISO-3"` says those are 3-letter codes, `color="anomalies"` shades by count, `hover_data` adds users to the tooltip, `Reds` is the colour scale, then the title.
  - **L40** `update_geos(showcountries=True, projection_type="natural earth")` draws borders and chooses a world projection.
  - **L41** margins. **L42** return.
- **L45-61** `anomaly_timeline(events)`:
  - **L47-48** empty guard.
  - **L49-58** `px.scatter`: x is time, y is score, colour by `is_anomaly`, `color_discrete_map` makes True red (`#d62728`) and False grey, `hover_data` lists extra tooltip fields, `labels` renames axes.
  - **L59** `update_traces(marker={"size": 6, "opacity": 0.75})` small translucent dots (so dense areas read well).
  - **L60** margins and legend title "Flagged". **L61** return.
- **L64-78** `iam_sunburst(hierarchy)`:
  - **L66-67** empty guard.
  - **L68-76** `px.sunburst`: `path=["role","policy","service"]` defines the rings from the centre outward; `values="count"` sizes each slice by how many permissions it holds; `color="risk_score"` colours by risk; `range_color=(0, 4)` fixes the scale to the full 0-4 range; `RdYlGn_r` is red-yellow-green reversed so high risk is red.
  - **L77** height 620. **L78** return.
  - *Note:* for numeric colour, Plotly averages the children's risk weighted by their size, so a role holding one admin action among many harmless ones can look less red than its worst permission. The table beside the chart shows the maximum.

---

## 8. `iam_analyzer/sample.py`: synthetic data (328 lines)

- **L1-7** docstring: deterministic fake CloudTrail with one compromised service account and one harmless odd login. All IPs come from documentation-reserved ranges (RFC 5737), so none belong to real machines.
- **L11** `import random`. **L12** `from datetime import datetime, timedelta, timezone`. **L13** `from typing import Any`.
- **L15-16** comment and the declaration of `_USERS`: a dictionary mapping each username to a tuple of (home country code, home IP, region, list of (event name, event source, weight)). The long type hint spells out that structure.
- **L17-60** the four users:
  - `alice` (USA, `203.0.113.10`, us-east-1): mostly `DescribeInstances` (weight 40) and `GetObject` (35).
  - `bob` (GBR, eu-west-2): mostly `PutObject` and `GetObject`.
  - `carol` (IND, ap-south-1): `DescribeInstances`, `GetMetricData`, a few `RunInstances`.
  - `svc-deploy` (USA, us-east-1): `UpdateService`, `DescribeServices`, `GetAuthorizationToken`.
  - The weight says how likely each event is, relative to the others for that user (`ConsoleLogin` has weight 5).
- **L62-63** `_ATTACK_IP = "192.0.2.77"` and `_ATTACK_COUNTRY = "RUS"`: the intruder.
- **L64-78** `_ATTACK_SEQUENCE`: the intruder's 13 steps in order, each (event, source, error-or-None): identity check, list users and roles, a denied `ListAccessKeys`, create user and access key, attach and write policies, change a trust policy, stop and attempt to delete CloudTrail (the delete is denied), read a secret, and change a bucket policy. This models recon, then privilege escalation, then covering tracks.
- **L81-108** `_record(...)`: builds one CloudTrail-shaped dictionary.
  - **L81-91** parameters; `error: str | None = None` and `agent = "aws-cli/2.15.0"` have defaults.
  - **L93** `when.strftime("%Y-%m-%dT%H:%M:%SZ")` formats the time as ISO text (`2025-03-03T08:15:00Z`).
  - **L94-98** `eventSource`, `eventName`, `awsRegion`, `sourceIPAddress`, `userAgent` with CloudTrail's real field names.
  - **L99-103** nested `userIdentity` with an ARN such as `arn:aws:iam::123456789012:user/alice` (123456789012 is a fake account id).
  - **L104** `country_iso3`: the non-standard enrichment field.
  - **L106-107** only add `errorCode` when an error was given.
  - **L108** return the dictionary.
- **L111-178** `generate_cloudtrail(seed=42, days=7)`:
  - **L113** `rng = random.Random(seed)`: a private random generator; the same seed always yields the same numbers.
  - **L114** `start = datetime(2025, 3, 3, tzinfo=timezone.utc)`: fixed start date, so output never depends on today's date.
  - **L115** empty list `records`.
  - **L117-130** normal traffic: for each day and each user, `rng.randint(35, 55)` events; `names = [e[:2] for e in events]` keeps just (event, source) from each triple; `weights = [e[2] for e in events]`; `rng.choices(names, weights)[0]` picks one weighted choice (returns a one-item list, hence `[0]`) and unpacks into `event, source`; `when` is the day plus a random hour 8-18, minute and second (business hours); `error` is `"AccessDenied"` about 1% of the time (`rng.random() < 0.01`); then `_record(...)` is appended.
  - **L132-144** the benign outlier: `bob` logs in from Brazil at 02:14 on day 3 with a browser agent. Unusual, but harmless; a good test of false positives.
  - **L146-161** the attack: `attack_start` is day 4 at 03:07; `enumerate(_ATTACK_SEQUENCE)` gives each step an index `i`; each step is dated 25 seconds apart (`25 * i`); the user is `svc-deploy`, IP and country are the intruder's, and the user-agent is `python-requests/2.31.0` (a script, unlike the usual `aws-cli`).
  - **L162-175** three failed console logins (`AccessDenied`) from the attacker's IP at 5, 4 and 3 minutes before the main attack: `attack_start - timedelta(minutes=5 - i)`.
  - **L177** `records.sort(key=lambda r: r["eventTime"])`: ISO timestamps sort correctly as text.
  - **L178** return `{"Records": records}`, the real CloudTrail wrapper. Count: 7 days x 4 users x 35-55 events, plus 1 + 13 + 3 injected; seed 42 produces 1,308.
- **L181-183** `attack_marker(record)`: True when a record came from the attacker IP. Tests use it to measure recall.
- **L186-328** `sample_policies()`: returns the demo roles.
  - **L188-197** `admin_trust`: a trust policy whose Principal is `{"AWS": "*"}`: anyone can assume the role. The bad example.
  - **L198-207** `account_trust`: only the account root may assume it. The good example.
  - **L211-220** `PlatformAdmin`: policy `FullAdmin` allows `*` on `*`. Expect critical.
  - **L222-244** `CiDeployRole`: open trust policy (critical), `ecs:*` on `*` (medium), `iam:PassRole` on `*` (high privilege-escalation primitive).
  - **L245-277** `DataScientist`: `S3ReadOnly` limited to two named resources (clean) and `SageMakerAccess` with `sagemaker:*` on `*` (medium).
  - **L278-304** `IamManager`: `iam:*` on `*` (high); a second policy `DenyDeleteTrail` with `Effect: Deny` (never counted as risky).
  - **L305-326** `ReadOnlyAuditor`: `cloudtrail:LookupEvents`, `iam:Get*`, `iam:List*` on `*`: broad but read-only, so low risk, no finding.

---

## 9. Tests

### `tests/test_loaders.py`
- **L1-6** imports: `json`, `pytest`, and from our package `COLUMNS`, `LogFormatError`, `load_events`, `generate_cloudtrail`.
- **L9-16** `test_cloudtrail_normalised`: generate data (seed 1), parse it, then assert: the columns equal `COLUMNS` exactly; the row count equals the record count (no row was dropped); provider is `aws` everywhere; times are sorted (`is_monotonic_increasing`); the user column contains `svc-deploy` once the ARN is cut at `/` (`str.split("/").str[-1]` takes the last piece).
- **L19-28** `test_ndjson_and_csv`: five records written one per line must parse to 5 rows; a tiny hand-written CSV must give user `alice` and country `UNK` (no country column).
- **L31-45** `test_azure_activity_log`: a `{"value": [...]}` document with a nested `operationName` and failed status must parse as provider `azure` with error `Failed`.
- **L48-64** `test_gcp_audit_log`: a GCP entry with status code 7 (permission denied) must parse as `gcp`, event `SetIamPolicy`, error code 7.
- **L67-71** `test_unknown_schema_rejected`: `pytest.raises(LogFormatError)` asserts the code raises our error for an unrecognised schema and for broken JSON.

### `tests/test_anomaly.py`
- **L10-17** `@pytest.fixture(scope="module") def scored()`: builds the scored data once for all tests in the file. It collects the attacker IPs with `attack_marker`, runs `detect_anomalies(contamination=0.03)`, and adds an `injected` column marking the attack rows.
- **L20-22** the three new columns exist and scores lie within 0..1 (`.between(0, 1).all()`).
- **L25-27** the share of flagged events is between 2% and 4% (close to the requested 3%).
- **L30-34** recall: of the injected attack events, at least 70% must be flagged; the message prints the actual percentage if it fails.
- **L37-41** the `AttachUserPolicy` attack event must be flagged and its reasons must mention "sensitive" and "unusual country".
- **L44-50** a frame of only 3 rows must not crash and must flag nothing.

### `tests/test_iam.py`
- **L5-13** `test_findings_cover_known_bad_policies`: builds a set of (role, issue) pairs and checks four expected findings exist, that the first (sorted) finding is `critical`, and that the hierarchy table is not empty.
- **L16-19** `DataScientist` must appear in findings (it has `sagemaker:*`) while `ReadOnlyAuditor` must not (read-only wildcards are low risk).
- **L22-25** every `Deny` row must have risk 0, and at least one Deny row must exist.
- **L28-30** `PlatformAdmin` must rank first in the role summary.
- **L33-35** an empty document gives two empty results and no error.

### `tests/test_app.py`
- **L4** imports `AppTest`, Streamlit's headless app tester.
- **L12** `APP = str(Path(__file__).resolve().parents[1] / "app.py")`: path to `app.py`, found relative to this test file (`parents[1]` is the repo root) so tests work from any directory.
- **L15-23** `test_figures_build`: the geo figure's first trace is a `choropleth` and includes `RUS`; the timeline has data; the sunburst's first trace is a `sunburst`.
- **L26-31** `test_figures_handle_empty`: with zero events, or an empty policy document, the functions return the message figure (a layout with an annotation) instead of crashing.
- **L34-37** `test_app_renders_with_sample_data`: `AppTest.from_file(APP, default_timeout=60).run()` actually runs the whole app headlessly; asserts no exception and that the first two metric tiles have the expected labels.

---

## 10. Known limitations spotted while writing this

1. `iam.py` lines 78-80 contain a redundant `if` (harmless).
2. A policy with `Action "*"` and limited resources is scored 3 but labelled "Wildcard action and resource (medium)".
3. An uploaded policy file that is valid JSON but the wrong shape (for example a top-level list) would raise an unhandled error in `analyze_policies`; only invalid JSON is caught in `app.py`.
4. The sunburst colour for a parent slice is a size-weighted average, not the maximum.
5. Anomaly accuracy is only demonstrated on synthetic data.
