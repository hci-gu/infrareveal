package timeline

import (
	"encoding/json"
	"myapp/observer"
	"testing"
)

func TestTimelineLODAndActivityAggregation(t *testing.T) {
	label, bucket, overview, err := parseTimelineLOD("500ms")
	if err != nil || label != "500ms" || bucket != 500 || overview {
		t.Fatalf("unexpected lod result: %q %d %v %v", label, bucket, overview, err)
	}
	record := map[string]any{
		"bucket_ms": 50,
		"samples": map[string]any{
			"version": 1, "bucket_ms": 50, "chunk_ms": 5000,
			"samples": [][]int64{{0, 10, 0, 1, 0}, {50, 0, 20, 0, 2}, {500, 5, 5, 1, 1}},
		},
	}
	aggregated := aggregateActivityRecord(record, 500)
	raw, _ := json.Marshal(aggregated["samples"])
	payload := observer.ActivitySamplePayload{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.BucketMS != 500 || len(payload.Samples) != 2 {
		t.Fatalf("unexpected aggregate: %#v", payload)
	}
	if payload.Samples[0][1] != 10 || payload.Samples[0][2] != 20 || payload.Samples[0][3] != 1 || payload.Samples[0][4] != 2 {
		t.Fatalf("unexpected first aggregate bin: %#v", payload.Samples[0])
	}
}
