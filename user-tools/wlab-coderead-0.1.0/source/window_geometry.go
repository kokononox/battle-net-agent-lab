package main

type windowRect struct {
	Left   int32 `json:"left"`
	Top    int32 `json:"top"`
	Right  int32 `json:"right"`
	Bottom int32 `json:"bottom"`
}

// Only position our own UI. No resizing and no modification of any game window.
func centerOwnWindow(w, work windowRect) (int32, int32, bool) {
	ww, wh := int64(w.Right)-int64(w.Left), int64(w.Bottom)-int64(w.Top)
	aw, ah := int64(work.Right)-int64(work.Left), int64(work.Bottom)-int64(work.Top)
	if ww <= 0 || wh <= 0 || aw <= 0 || ah <= 0 {
		return 0, 0, false
	}
	dx, dy := (aw-ww)/2, (ah-wh)/2
	if dx < 0 {
		dx = 0
	}
	if dy < 0 {
		dy = 0
	}
	return int32(int64(work.Left) + dx), int32(int64(work.Top) + dy), true
}
