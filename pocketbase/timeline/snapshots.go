package timeline

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"myapp/data"
)

const snapshotTTL = 15 * time.Second

type pageSnapshot struct {
	id, session, kind, epoch string
	at                       time.Time
	size                     int
	from                     int64
	query                    pageCursor
	window                   data.MapWindow
	blocks                   data.BlockPage
}

// Window and Blocks pin multi-page reads in one bounded typed cache. Requiring
// every page to outrun the live flush cadence would starve a busy session.
func (r *Reader) Window(id string, q Query) (data.MapWindow, error) {
	if q.cursor != "" {
		snapshot, offset, err := r.continueSnapshot(id, q, "map")
		if err != nil {
			return data.MapWindow{}, err
		}
		if offset > len(snapshot.window.Series) {
			return data.MapWindow{}, fmt.Errorf("%w: invalid cursor offset", ErrInvalidQuery)
		}
		return windowPage(snapshot, q, offset), nil
	}
	snapshot, err := r.readWindow(id, q)
	if err != nil || len(snapshot.window.Series) <= q.limit {
		return snapshot.window, err
	}
	return windowPage(r.cacheSnapshot(snapshot), q, 0), nil
}

func (r *Reader) Blocks(id string, q Query) (data.BlockPage, error) {
	if q.cursor != "" {
		snapshot, offset, err := r.continueSnapshot(id, q, "blocks")
		if err != nil {
			return data.BlockPage{}, err
		}
		if offset > len(snapshot.blocks.Items) {
			return data.BlockPage{}, fmt.Errorf("%w: invalid cursor offset", ErrInvalidQuery)
		}
		return blockPage(snapshot, q, offset), nil
	}
	snapshot, err := r.readBlocks(id, q)
	if err != nil || len(snapshot.blocks.Items) <= q.limit {
		return snapshot.blocks, err
	}
	return blockPage(r.cacheSnapshot(snapshot), q, 0), nil
}

func (r *Reader) cacheSnapshot(snapshot pageSnapshot) pageSnapshot {
	snapshot.id, snapshot.at = data.NewID(), time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	retained := r.snapshots[:0]
	total := snapshot.size
	for _, item := range r.snapshots {
		if snapshot.at.Sub(item.at) < snapshotTTL {
			retained = append(retained, item)
			total += item.size
		}
	}
	clear(r.snapshots[len(retained):])
	r.snapshots = append(retained, snapshot)
	for len(r.snapshots) > 8 || total > 32*1024*1024 {
		total -= r.snapshots[0].size
		r.snapshots[0] = pageSnapshot{}
		r.snapshots = r.snapshots[1:]
	}
	return snapshot
}

func (r *Reader) continueSnapshot(id string, q Query, kind string) (pageSnapshot, int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(q.cursor)
	if err != nil {
		return pageSnapshot{}, 0, fmt.Errorf("%w: invalid cursor", ErrInvalidQuery)
	}
	var cursor pageCursor
	if err := json.Unmarshal(raw, &cursor); err != nil || cursor.Snapshot == "" {
		return pageSnapshot{}, 0, fmt.Errorf("%w: invalid cursor", ErrInvalidQuery)
	}
	r.mu.Lock()
	var found *pageSnapshot
	for _, snapshot := range r.snapshots {
		if snapshot.id == cursor.Snapshot && snapshot.session == id && snapshot.kind == kind && time.Since(snapshot.at) < snapshotTTL {
			copy := snapshot
			found = &copy
			break
		}
	}
	r.mu.Unlock()
	if found == nil {
		return pageSnapshot{}, 0, ErrRevisionChanged
	}
	if q.from != found.query.From || q.to != found.query.To || q.resolution != found.query.Resolution || q.block != found.query.Block {
		return pageSnapshot{}, 0, fmt.Errorf("%w: cursor does not match this request", ErrInvalidQuery)
	}
	revision := found.window.Revision
	if kind == "blocks" {
		revision = found.blocks.Revision
	}
	offset, err := q.offset(revision)
	if err != nil {
		return pageSnapshot{}, 0, err
	}
	// Retention, deletion and clear are authoritative. Capture epoch also
	// catches a clear inside the same source bin, when its floor cannot move.
	manifest, err := r.Manifest(id, time.Now())
	if err != nil {
		return pageSnapshot{}, 0, err
	}
	if manifest.RetainedFromMS > found.from || manifest.Capture.Epoch != found.epoch {
		return pageSnapshot{}, 0, ErrRevisionChanged
	}
	return *found, offset, nil
}

func queryCursor(q Query) pageCursor {
	return pageCursor{From: q.from, To: q.to, Resolution: q.resolution, Block: q.block}
}

func snapshotCursor(snapshot pageSnapshot, revision int64, offset int) string {
	cursor := snapshot.query
	cursor.Revision, cursor.Offset, cursor.Snapshot = revision, offset, snapshot.id
	encoded, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func windowPage(snapshot pageSnapshot, q Query, offset int) data.MapWindow {
	result := snapshot.window
	end := min(offset+q.limit, len(result.Series))
	result.Series = result.Series[offset:end]
	result.Complete = end == len(snapshot.window.Series)
	if !result.Complete {
		result.NextCursor = snapshotCursor(snapshot, result.Revision, end)
	}
	referenced := map[string]bool{}
	for _, chunk := range result.Series {
		referenced[chunk.DestinationID] = true
	}
	result.Destinations = make([]data.Destination, 0, len(snapshot.window.Destinations))
	for _, destination := range snapshot.window.Destinations {
		if referenced[destination.ID] {
			result.Destinations = append(result.Destinations, destination)
		}
	}
	return result
}

func blockPage(snapshot pageSnapshot, q Query, offset int) data.BlockPage {
	result := snapshot.blocks
	end := min(offset+q.limit, len(result.Items))
	result.Items = result.Items[offset:end]
	if end < len(snapshot.blocks.Items) {
		result.NextCursor = snapshotCursor(snapshot, result.Revision, end)
	}
	return result
}
