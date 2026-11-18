# Country footprints

`countries.json` contains Natural Earth's public-domain 1:110m Admin 0 country
polygons and label coordinates, rounded to three decimal places. Vendored from:
https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson

License: https://www.naturalearthdata.com/about/terms-of-use/

Label coordinates are layout anchors, not endpoint locations. Small territories
missing from this overview dataset still receive a country-level label without a
city pin or column. Country names and ISO alpha-2 codes are matched; the source
GeoIP country name remains the evidence for classifying a location.

# Submarine cables

`cables.json` holds submarine cable geometry from the TeleGeography Submarine
Cable Map (submarinecablemap.com, `cable-geo.json`, imported 2026-11-18).
Regenerate it with `node scripts/import-cable-data.mjs path/to/cable-geo.json`.
The export has no in-service dates; planned cables that distort inferred paths
are excluded by id in `../seaCrossings.ts` (`NOT_IN_SERVICE`).

Kept per cable: id, name, colour and line geometry (rounded to ~10 m). Derived at
import time:

- **Landings:** line ends that do not touch another line of the same cable
  within 10 km (those are branching units). Each landing's country comes from
  the Natural Earth outlines, or the nearest coastline within 120 km; landings
  without a country (mostly small islands) are dropped.
- **Joins:** links the browser adds to the cable's lines: branch ends snapped to
  the line they touch, and bridges between pieces of one cable within 100 km
  (separate landing stations, branches drawn short of the trunk).
- **Distances:** for every landing pair, the length along the cable's lines and
  joins (null where pieces are further apart, mostly regional networks).

Attribute TeleGeography wherever the data is shown.
