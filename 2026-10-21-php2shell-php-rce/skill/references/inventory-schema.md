# Offline CSV Evidence Format

Use UTF-8 (a BOM is accepted) with column names in the first row. Neither mode accesses the network or executes input paths.

## `inventory`: PHP Asset Inventory

Required columns: `asset,service,php_version,version_source,internet_exposed,owner`. Empty values are reported as evidence gaps; at least one asset row is required. Set `internet_exposed` to `yes`, `no`, or `unknown`; other values are invalid evidence and are not treated as `no`. A plain upstream three-part `php_version`, such as `8.5.12`, is compared only with the threshold for **its own branch**. Verify unrecognized versions and vendor backports separately. In `version_source`, record collection time, worker/package source, and node. Keep separate rows for multiple services on one asset.

```csv
asset,service,php_version,version_source,internet_exposed,owner
web-01,storefront,8.5.11,distribution package inventory on web-01 2026-10-21,yes,web-team
job-02,batch,,,unknown,platform-team
```

Example versions illustrate the format only. A distribution may backport the fix; check its advisory and package revision rather than treating `php_version` alone as proof of safety or exposure.

## `processes`: Existing Process-Creation Events

Required columns: `asset,timestamp,parent_image,child_image`. Extra columns are allowed but are not read or echoed. Export from a trusted internal logging system and retain the source time zone. Generic leads are selected by **executable basename** across Windows and POSIX paths. Custom process names, script wrappers, and lost parent-child relationships in containers may not be recognized.

```csv
asset,timestamp,parent_image,child_image
web-01,2026-10-21T10:00:00Z,/usr/sbin/php-fpm,/usr/bin/sh
web-01,2026-10-21T10:01:00Z,/usr/sbin/php-fpm,/usr/bin/convert
```

The first example is an investigative lead only. The second not matching does not establish that it is benign. Do not include actual full command lines, tokens, or request bodies in a shared inventory.
