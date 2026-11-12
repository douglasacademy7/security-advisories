# Security Advisory Time Based Blind SQL Injection in Modified Shop

## 1. General Information

| Field | Information |
|---|---|
| Product | Modified eCommerce Shopsoftware |
| Version analyzed | 3.3.0 |
| Revision | 16825 |
| Component | Administration - Banner Statistics |
| Affected endpoint | `admin/banner_statistics.php` |
| Affected code | `admin/includes/graphs/banner_daily.php` |
| Vulnerability | Time-Based Blind SQL Injection |
| CWE | CWE-89 |
| OWASP Top 10 | A03:2021 - Injection |
| Authentication | Administrative session required |
| CVSS | To be determined |
| CVE status | Pending assignment |
| Status | Confirmed through repeated timing tests |

## 2. Summary

A Time-Based Blind SQL Injection vulnerability was confirmed in the `year` parameter of the administrative banner statistics functionality in Modified Shop.

Source review identified direct interpolation of the user-controlled GET parameter into a SQL query. Repeated laboratory tests showed a consistent response delay when the `SLEEP(1)` probe was supplied, while baseline and control requests remained fast.

Five baseline requests had a median response time of 19 ms, five control requests had a median of 18 ms, and five probe requests had a median of 2,021 ms. All requests returned HTTP 200. No data extraction, modification, or deletion was performed.

## 3. Affected Endpoint

**Endpoint used during the empirical validation:**

```http
GET /admin/banner_statistics.php?bID=1&gID=1&page=1&type=daily&year=2025%27%20OR%20SLEEP(1)%20%23
```

**Decoded payload:**

```sql
2025' OR SLEEP(1) #
```

The source model also documented a `SLEEP(5)` probe. The lower-impact `SLEEP(1)` payload was used for the repeated timing confirmation.

## 4. Identified Parameters

| Parameter | Method | Purpose |
|---|---|---|
| `bID` | GET | Identifies the banner record |
| `gID` | GET | Selects the statistics group or view |
| `page` | GET | Selects the administrative page |
| `type` | GET | Selects the statistics period |
| `year` | GET | Vulnerable value used in the SQL query |

## 5. Technical Evidence

### 5.1. Source Data Flow

File: `admin/includes/graphs/banner_daily.php`

**Line 24 - User-controlled input:**

```php
$year = isset($_GET['year']) ? $_GET['year'] : date('Y');
```

The value is then concatenated directly into the SQL query:

```php
"and year(banners_history_date) = '" . $year . "'"
```

The reviewed code does not show prepared statements or SQL-safe parameter binding for the `year` value at this point.

### 5.2. Query Context

```sql
select dayofmonth(banners_history_date) as banner_day,
banners_shown as value,
banners_clicked as dvalue
from TABLE_BANNERS_HISTORY
where banners_id = '$banner_id'
and month(banners_history_date) = '$month'
and year(banners_history_date) = '$year'
```

The payload terminates the quoted year value, adds an `OR SLEEP(1)` expression, and uses the MySQL or MariaDB comment marker `#` to ignore the trailing quote.

### 5.3. Timing Evidence

| Test case | Observed times | Median | HTTP |
|---|---:|---:|---:|
| Baseline: `year=2025` | 43, 18, 17, 19, 20 ms | 19 ms | 200 |
| Control: `SLEEP(0)` | 19, 20, 18, 17, 17 ms | 18 ms | 200 |
| Probe: `SLEEP(1)` | 2021, 2022, 2021, 2021, 2019 ms | 2,021 ms | 200 |

The probe produced a consistent increase of approximately two seconds in all five attempts. The exact multiple of the requested delay may depend on the number of rows evaluated or on repeated execution of the affected query, but the timing separation is sufficient to confirm the injection behavior in this laboratory.

### 5.4. Reflection Note

The supplied `year` value was visible in the page title as text. This reflection is not, by itself, evidence of Cross-Site Scripting. The confirmed finding in this test is SQL Injection based on direct query construction and repeatable timing behavior.

## 6. Access Control

The affected functionality is protected by the administrative application context. The reviewed application bootstrap performs administrative-context, session, and permission checks before the feature is reached.

The exploitation prerequisite is an authenticated administrative user with permission to access banner statistics. The finding was validated only against the local laboratory instance.

## 7. Impact

Exploitation may allow:

- Inference of database information through conditional response timing, depending on database permissions and query context;
- Potential degradation of availability through deliberately delayed database queries;
- Exposure of a database-backed administrative function to SQL manipulation by an authorized user;
- Possible expansion of impact if other concatenated parameters or database privileges are also insufficiently protected.

No data extraction, data modification, stacked statements, file access, or destructive operation was performed during the laboratory validation.

## 8. Classification

| Reference | Classification |
|---|---|
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command |
| OWASP Top 10 2021 | A03 - Injection |
| Category | Time-Based Blind SQL Injection |
| Affected parameter | `year` |
| CVSS | Pending evaluation |

## 9. Remediation Recommendation

It is recommended to:

1. Replace string concatenation with prepared statements or the parameter-binding mechanism provided by the application database layer;
2. Validate `year` as an integer before it reaches the query;
3. Apply equivalent validation and parameter binding to `bID`, `gID`, `page`, `type`, `month`, and other request-controlled values;
4. Use allowlists for period and report-type values where applicable;
5. Apply least-privilege permissions to the application database account;
6. Review database and application logs for abnormal query delays and repeated SLEEP-like probes;
7. Retest the endpoint after remediation with both valid input and the laboratory probe.

Complementary input validation:

```php
$year = filter_input(INPUT_GET, 'year', FILTER_VALIDATE_INT);
if ($year === false || $year === null) {
    $year = (int) date('Y');
}
```

Type validation is complementary and does not replace prepared statements or bound query parameters.

## 10. References

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## 11. Investigation Status

- [x] Affected administrative endpoint identified;
- [x] Vulnerable `year` parameter identified;
- [x] Direct SQL interpolation confirmed in source;
- [x] Baseline and control timing measurements collected;
- [x] Time-based behavior reproduced in five of five probe requests;
- [x] No data extraction or modification performed;
- [ ] Define final CVSS score and disclosure timeline;
- [ ] Confirm the remediation in a patched build.

---

**Researcher:** Douglas Dias (V0rkael)

**Organization:** RedScan Academy

**Area:** Offensive Security / Vulnerability Research

**Report Type:** Security Advisory
