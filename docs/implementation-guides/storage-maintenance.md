# Storage and maintenance

Open **Sessions → Storage & maintenance** (`/storage`). All maintenance mutations
are manual. Existing rolling recording retention and log policies are unchanged.

## Disk information

The gateway reads filesystem capacity and available space from the filesystem
containing its data directory, including the host's other disk consumers. It
reports low space below 2 GiB or 15% available, critical below 512 MiB or 5%, and
read-only filesystems separately. These are status indicators, not automatic
cleanup thresholds. SD-card wear, remaining life and hardware integrity are not
inferred from disk capacity.

Recording and application-log panels show their database and WAL file sizes,
plus unused SQLite pages available for reuse. Refresh storage fetches new
measurements and indexed traffic-record counts per session. It does not scan
Docker, run integrity checks, checkpoint, vacuum or delete files.

## Delete sessions

Delete is available on the session cards and maintenance page. Confirmation
names the session and explains permanent deletion. The server removes its
traffic chunks, coverage, activity blocks, route evidence and optional diagnostic
rows transactionally. Destination records shared with another session survive;
unreferenced destinations are removed. Network-wide probe admissions remain
charged through their existing operational retention horizon.

Deleting a live recording first drains capture and route work. Its deletion and
creation of a fresh active session commit together. The new session preserves
rolling retention settings (and continuous-demo behavior), with a new identity.
Failure rolls the transaction back. Deleting a synthetic simulation joins its
separate observer before removing its session. Saved sessions can be deleted
without removing other recordings.

SQLite reuses deleted pages; file size and filesystem free space may not change
immediately. This feature does not automatically compact databases, remove
Docker images or delete host logs/backups.

## Refresh GeoIP

The source remains **MaxMind GeoLite2 City**. Under MaxMind settings, enter the
account ID and a license key with database-download access. Settings are saved
only on the gateway as `maxmind.json` in its persistent data directory, with
mode 0600. Status responses expose the account ID and configured flag, never
the saved key. An empty key keeps the existing key only for the same account.

Refresh downloads MaxMind's official HTTPS tar.gz permalink using Basic Auth
and follows its normal download redirect. It streams one expected regular MMDB
file to a temporary file beside the installed database, checks archive integrity,
validates the entire MMDB and its edition, and rejects older builds. It then
atomically replaces the old file and swaps the shared lookup reader. Failed
updates keep the old database usable. A matching build is reported as already
current. Downloads and expanded archives are bounded to 512 MiB, with a ten-minute
timeout and one refresh at a time. Shutdown cancels and joins the download.

The dashboard shows download/validation progress and errors; reopening the page
reattaches to a running job. Installation invalidates in-memory destination and
route-location caches for new observations. Stored observations keep their
original geography. No proxy restart or automatic update schedule is required.
The optional ASN database is unchanged.

Docker must mount `GEOIP_DIR` writable. The default City path inside the container
is `/root/geoip/city.mmdb`; `GEOIP_CITY_DB` can override it. Existing read-only
custom mounts produce an actionable refresh error and leave the current file
untouched. Preserve `maxmind.json` with the rest of the private application data;
do not commit it or include it in shared test reports.

Reference: [MaxMind download documentation](https://dev.maxmind.com/geoip/updating-databases/).

## Pi deployment verification — 12 November 2026

Feature revision `775345c5aed6cc776e1ee83727762d18a5a73f6c` is deployed from
`/home/pi/Documents/infrareveal-releases/775345c-maintenance-20261112`.
The original checkout was left unchanged. Online backups of both databases
passed `quick_check` before deployment. The prior release can be restored with
`sudo /home/pi/Documents/infrareveal-backups/20261112-before-775345c-maintenance-20261112/rollback.sh`.
That script switches application images without restoring or deleting recordings.

Validation passed: the full Go suite; race checks for geolocation, gateway,
observer and routing; 145 frontend tests; workspace lint; and the production
dashboard build. Browser checks covered cancellation and confirmed deletion in
an isolated local database, credential setup, progress/error behavior in tests,
and desktop/mobile layout. Download tests used a local HTTP server and an
official MaxMind test database, including corrupt and interrupted downloads.

On the Pi, the storage page rendered correctly, capacity matched the host
filesystem, all 20 dashboard asset hashes and both executable hashes matched
the release, the existing session was preserved, and live capture advanced
without additional reported drops during the smoke check. No production
recordings were deleted and no client load experiment was run.

At verification the filesystem had about 1.9 GiB available, the recording
database plus journal used 1.7 MiB, and the application log database plus journal
used 41.3 MiB. The installed GeoLite2 City file was 55.3 MiB, with an internal
build date of 7 February 2025 (distinct from its filesystem modification date).
It was preserved byte-for-byte. A licensed production download still requires
entering the account ID and license key in MaxMind settings; it has not been
claimed as verified without those credentials.
