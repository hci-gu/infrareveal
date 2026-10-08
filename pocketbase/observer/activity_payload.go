package observer

// ActivitySamplePayload is the versioned packet activity storage/wire codec.
// Each sample is [offset_ms, payload_out, payload_in, packets_out, packets_in].
type ActivitySamplePayload struct {
	Version  int       `json:"version"`
	BucketMS int       `json:"bucket_ms"`
	ChunkMS  int       `json:"chunk_ms"`
	Samples  [][]int64 `json:"samples"`
}
