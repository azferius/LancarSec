package utils

import (
	"image"
	"image/color"
	"testing"
)

// fillRGBA paints every pixel of img with c.
func fillRGBA(img *image.RGBA, c color.RGBA) {
	b := img.Bounds()
	for x := b.Min.X; x < b.Max.X; x++ {
		for y := b.Min.Y; y < b.Max.Y; y++ {
			img.SetRGBA(x, y, c)
		}
	}
}

// countOpaque returns how many pixels in img have a non-zero alpha.
func countOpaque(img *image.RGBA) int {
	n := 0
	b := img.Bounds()
	for x := b.Min.X; x < b.Max.X; x++ {
		for y := b.Min.Y; y < b.Max.Y; y++ {
			if img.RGBAAt(x, y).A != 0 {
				n++
			}
		}
	}
	return n
}

// opaqueBounds returns the smallest rectangle covering every non-transparent
// pixel, plus how many there were. The rectangle is empty when n == 0.
func opaqueBounds(img *image.RGBA) (image.Rectangle, int) {
	minX, minY := 1<<30, 1<<30
	maxX, maxY := -1<<30, -1<<30
	n := 0
	b := img.Bounds()
	for x := b.Min.X; x < b.Max.X; x++ {
		for y := b.Min.Y; y < b.Max.Y; y++ {
			if img.RGBAAt(x, y).A == 0 {
				continue
			}
			n++
			if x < minX {
				minX = x
			}
			if y < minY {
				minY = y
			}
			if x > maxX {
				maxX = x
			}
			if y > maxY {
				maxY = y
			}
		}
	}
	if n == 0 {
		return image.Rectangle{}, 0
	}
	return image.Rect(minX, minY, maxX+1, maxY+1), n
}

var (
	transparent = color.RGBA{}
	red         = color.RGBA{R: 255, G: 0, B: 0, A: 255}
	green       = color.RGBA{R: 0, G: 255, B: 0, A: 255}
)

// ---------------------------------------------------------------------------
// AddLabel
//
// Deliberately NOT golden-tested against pixel data: the glyph bitmaps come
// from golang.org/x/image/font/basicfont, so a dependency bump would flip a
// pixel golden without any change in this repo. Structural invariants only.
// ---------------------------------------------------------------------------

func TestAddLabelWritesPixelsAndKeepsBounds(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 60, 30))
	before := img.Bounds()

	if got := countOpaque(img); got != 0 {
		t.Fatalf("fresh image already has %d opaque pixels", got)
	}

	AddLabel(img, 2, 20, "AB", color.RGBA{R: 61, G: 140, B: 64, A: 255})

	if got := countOpaque(img); got == 0 {
		t.Fatal("AddLabel wrote no visible pixels; it is supposed to mutate the image in place")
	}
	if img.Bounds() != before {
		t.Errorf("AddLabel changed the image bounds: %v -> %v", before, img.Bounds())
	}
}

func TestAddLabelEdgeCasesDoNotPanic(t *testing.T) {
	tests := []struct {
		name  string
		x, y  int
		label string
	}{
		{name: "origin baseline, glyph clipped above", x: 0, y: 0, label: "X"},
		{name: "empty label", x: 5, y: 15, label: ""},
		{name: "far negative coordinates", x: -1000, y: -1000, label: "hello"},
		{name: "far positive coordinates", x: 10000, y: 10000, label: "hello"},
		{name: "baseline exactly on the bottom edge", x: 0, y: 30, label: "hello"},
		{name: "label wider than the image", x: 0, y: 20, label: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "non-ascii runes fall back to the missing glyph", x: 0, y: 20, label: "héllo→"},
		{name: "control characters", x: 0, y: 20, label: "a\x00\n\tb"},
		{name: "fully transparent colour", x: 0, y: 20, label: "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := image.NewRGBA(image.Rect(0, 0, 60, 30))
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("AddLabel(%d, %d, %q) panicked: %v", tt.x, tt.y, tt.label, r)
				}
			}()
			AddLabel(img, tt.x, tt.y, tt.label, color.RGBA{R: 61, G: 140, B: 64, A: 255})
			if img.Bounds() != image.Rect(0, 0, 60, 30) {
				t.Errorf("bounds changed to %v", img.Bounds())
			}
		})
	}
}

// AddLabel's two int parameters are (x, y) and they are NOT interchangeable:
// x is the horizontal pen position and y is the BASELINE, so the glyph box sits
// to the right of x and ABOVE y. Transposing them into the fixed.Point26_6 is
// the kind of same-type argument swap a refactor of the captcha renderer can
// introduce for free — middleware.go:246-248 passes two random offsets
// positionally — and every other AddLabel test here (pixels written, bounds
// unchanged, no panic, clipped when far outside) is blind to it.
//
// Asserted structurally rather than as a pixel golden, so a basicfont bump
// cannot flip it: the ink must land inside the cell the (x, y) pen position
// defines, using generous margins around basicfont.Face7x13's 7x13 cell
// (ascent 11, descent 2). Today "M" at (3, 30) inks x[3..8] y[21..29];
// transposed it inks x[30..35] y[0..2].
func TestAddLabelTreatsTheFirstArgumentAsXAndTheSecondAsTheBaseline(t *testing.T) {
	const penX, baselineY = 3, 30

	img := image.NewRGBA(image.Rect(0, 0, 80, 60))
	AddLabel(img, penX, baselineY, "M", color.RGBA{R: 255, G: 255, B: 255, A: 255})

	box, n := opaqueBounds(img)
	if n == 0 {
		t.Fatal("AddLabel wrote no pixels at all; with an 80x60 canvas the glyph should be fully visible — the pen position was not where the arguments say it is")
	}

	// Horizontal: the glyph starts at the pen and is one 7px cell wide. Allow
	// two cells of slack for any future face.
	if box.Min.X < penX || box.Max.X > penX+14 {
		t.Errorf("ink spans x[%d..%d), want it inside [%d..%d) — the x argument is not being used as the horizontal pen position", box.Min.X, box.Max.X, penX, penX+14)
	}
	// Vertical: the glyph hangs off the baseline, so it sits above y and may
	// descend a couple of pixels below it. Allow a 16px ascent / 5px descent.
	if box.Min.Y < baselineY-16 || box.Max.Y > baselineY+5 {
		t.Errorf("ink spans y[%d..%d), want it inside [%d..%d) — the y argument is not being used as the baseline", box.Min.Y, box.Max.Y, baselineY-16, baselineY+5)
	}
}

// The same swap seen from the other side: two labels that differ ONLY in their
// x argument must move horizontally, and two that differ only in y must move
// vertically. A transposed point makes each move along the wrong axis.
func TestAddLabelXAndYMoveTheGlyphAlongTheirOwnAxes(t *testing.T) {
	draw := func(x, y int) image.Rectangle {
		img := image.NewRGBA(image.Rect(0, 0, 80, 60))
		AddLabel(img, x, y, "M", color.RGBA{R: 255, G: 255, B: 255, A: 255})
		box, n := opaqueBounds(img)
		if n == 0 {
			t.Fatalf("AddLabel(%d, %d) wrote nothing", x, y)
		}
		return box
	}

	base := draw(10, 40)
	movedX := draw(30, 40)
	movedY := draw(10, 20)

	if movedX.Min.Y != base.Min.Y || movedX.Max.Y != base.Max.Y {
		t.Errorf("changing only x moved the ink vertically: %v -> %v", base, movedX)
	}
	if movedX.Min.X-base.Min.X != 20 {
		t.Errorf("changing x by +20 moved the ink horizontally by %d (%v -> %v), want 20", movedX.Min.X-base.Min.X, base, movedX)
	}
	if movedY.Min.X != base.Min.X || movedY.Max.X != base.Max.X {
		t.Errorf("changing only y moved the ink horizontally: %v -> %v", base, movedY)
	}
	if movedY.Min.Y-base.Min.Y != -20 {
		t.Errorf("changing y by -20 moved the ink vertically by %d (%v -> %v), want -20", movedY.Min.Y-base.Min.Y, base, movedY)
	}
}

// A label drawn entirely outside the destination is clipped away, not written
// and not an error. Pins that the captcha's random label placement
// (middleware.go:246-248 uses rand offsets) can silently produce a blank layer.
func TestAddLabelFullyOutsideBoundsWritesNothing(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 60, 30))
	AddLabel(img, 5000, 5000, "ABC", color.RGBA{R: 255, G: 255, B: 255, A: 255})
	if got := countOpaque(img); got != 0 {
		t.Errorf("AddLabel far outside bounds wrote %d pixels, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// WarpImg
// ---------------------------------------------------------------------------

func TestWarpImgIdentityDisplacementCopiesEveryPixel(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 8, 6))
	for x := 0; x < 8; x++ {
		for y := 0; y < 6; y++ {
			src.SetRGBA(x, y, color.RGBA{R: uint8(x * 10), G: uint8(y * 10), B: 7, A: 255})
		}
	}

	dst := WarpImg(src, func(x, y int) (int, int) { return x, y })

	if dst.Bounds() != src.Bounds() {
		t.Fatalf("WarpImg bounds = %v, want %v", dst.Bounds(), src.Bounds())
	}
	for x := 0; x < 8; x++ {
		for y := 0; y < 6; y++ {
			if got, want := dst.RGBAAt(x, y), src.RGBAAt(x, y); got != want {
				t.Fatalf("dst(%d,%d) = %v, want %v", x, y, got, want)
			}
		}
	}
}

func TestWarpImgReturnsANewImageAndLeavesSourceUntouched(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 4, 4))
	fillRGBA(src, red)

	dst := WarpImg(src, func(x, y int) (int, int) { return 0, 0 })

	if dst == src {
		t.Fatal("WarpImg returned the source image; it must allocate a new one")
	}
	if got := countOpaque(src); got != 16 {
		t.Errorf("WarpImg mutated the source: %d opaque pixels remain, want 16", got)
	}
	// Every destination pixel sampled src(0,0), which is red.
	for x := 0; x < 4; x++ {
		for y := 0; y < 4; y++ {
			if got := dst.RGBAAt(x, y); got != red {
				t.Fatalf("dst(%d,%d) = %v, want %v", x, y, got, red)
			}
		}
	}
}

func TestWarpImgPreservesNonZeroOrigin(t *testing.T) {
	src := image.NewRGBA(image.Rect(5, 7, 15, 17))
	fillRGBA(src, green)

	dst := WarpImg(src, func(x, y int) (int, int) { return x, y })

	if want := image.Rect(5, 7, 15, 17); dst.Bounds() != want {
		t.Fatalf("WarpImg bounds = %v, want %v", dst.Bounds(), want)
	}
	if got := countOpaque(dst); got != 100 {
		t.Errorf("dst has %d opaque pixels, want 100", got)
	}
}

func TestWarpImgOutOfRangeDisplacementLeavesPixelUnset(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 4, 4))
	fillRGBA(src, red)

	// Displacement points far outside the source on both axes; the guard skips
	// the copy and the destination pixel keeps its zero value.
	dst := WarpImg(src, func(x, y int) (int, int) { return -100, -100 })

	if got := countOpaque(dst); got != 0 {
		t.Errorf("dst has %d opaque pixels, want 0 (all displacements were rejected)", got)
	}
}

// funcImage is an image.Image whose At() is defined everywhere, including
// outside Bounds(). It exists to make the off-by-one in WarpImg's guard
// OBSERVABLE — with an *image.RGBA source the difference is invisible, because
// RGBA.At() already returns the zero colour outside its rectangle and the
// destination pixel is zero either way.
type funcImage struct {
	rect image.Rectangle
	at   func(x, y int) color.Color
}

func (f funcImage) ColorModel() color.Model { return color.RGBAModel }
func (f funcImage) Bounds() image.Rectangle { return f.rect }
func (f funcImage) At(x, y int) color.Color { return f.at(x, y) }

// BUG (a later wave flips this): WarpImg's guard is
//
//	if dx < minX || dx > maxX || dy < minY || dy > maxY { continue }
//
// but an image.Rectangle's Max is EXCLUSIVE, so the correct upper bound is
// `>= maxX` / `>= maxY`. As written, a displacement landing exactly on maxX or
// maxY is accepted and src.At() is called one pixel outside the source
// rectangle. For an *image.RGBA source that read returns the zero colour so the
// defect is invisible in production today; this test uses a source whose At()
// is defined out of bounds to prove the out-of-range read really happens. When
// the comparison is tightened to >=, these pixels become transparent and the
// assertions below flip.
func TestWarpImgReadsOnePixelPastTheUpperBound(t *testing.T) {
	const w, h = 4, 4
	sentinel := color.RGBA{R: 1, G: 2, B: 3, A: 255}
	inside := color.RGBA{R: 9, G: 9, B: 9, A: 255}

	src := funcImage{
		rect: image.Rect(0, 0, w, h),
		at: func(x, y int) color.Color {
			if x == w || y == h {
				return sentinel // strictly outside Bounds()
			}
			return inside
		},
	}

	// Every destination pixel samples (maxX, maxY) == (4, 4), which is outside
	// the source rectangle. Today the guard lets it through.
	dst := WarpImg(src, func(x, y int) (int, int) { return w, h })

	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			if got := dst.RGBAAt(x, y); got != sentinel {
				t.Fatalf("dst(%d,%d) = %v, want %v — today WarpImg accepts dx==maxX/dy==maxY and reads out of bounds", x, y, got, sentinel)
			}
		}
	}

	// One past that (maxX+1) IS rejected, so the guard is off by exactly one.
	dst2 := WarpImg(src, func(x, y int) (int, int) { return w + 1, h + 1 })
	if got := countOpaque(dst2); got != 0 {
		t.Errorf("displacement to (maxX+1, maxY+1) produced %d opaque pixels, want 0", got)
	}
}

// WarpImg's guard has FOUR clauses — dx below minX, dx above maxX, dy below
// minY, dy above maxY — and each one is load-bearing on its own. Deleting
// either Y clause (the routine casualty of a guard being "simplified" or
// rewritten) leaves a source read that is out of range on the vertical axis
// only, which every other WarpImg test here misses: they all displace both axes
// together, so the surviving X clause covers for the missing Y one.
//
// The displacement closure is caller-supplied — the captcha passes an arbitrary
// wobble function — so an unguarded axis is a genuine out-of-range read on an
// arbitrary image.Image. funcImage makes that read observable: its At() is
// defined everywhere and returns an opaque sentinel outside Bounds(), where an
// *image.RGBA would have quietly returned the zero colour and hidden the bug.
func TestWarpImgRejectsAnOutOfRangeYEvenWhenXIsInRange(t *testing.T) {
	const w, h = 4, 4
	sentinel := color.RGBA{R: 1, G: 2, B: 3, A: 255}
	inside := color.RGBA{R: 9, G: 9, B: 9, A: 255}

	src := funcImage{
		rect: image.Rect(0, 0, w, h),
		at: func(x, y int) color.Color {
			if x < 0 || x >= w || y < 0 || y >= h {
				return sentinel // strictly outside Bounds()
			}
			return inside
		},
	}

	tests := []struct {
		name string
		dy   int
	}{
		{name: "dy far above maxY", dy: h + 50},
		{name: "dy one past maxY", dy: h + 1},
		{name: "dy far below minY", dy: -50},
		{name: "dy one below minY", dy: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// x is deliberately left in range, so ONLY the Y half of the guard
			// can reject this displacement.
			dst := WarpImg(src, func(x, y int) (int, int) { return x, tt.dy })

			if got := countOpaque(dst); got != 0 {
				t.Fatalf("displacement (x, %d) produced %d opaque pixels, want 0 — WarpImg read outside the source rectangle on the Y axis", tt.dy, got)
			}
			if got := dst.RGBAAt(0, 0); got == sentinel {
				t.Fatalf("dst(0,0) = %v, the out-of-bounds sentinel: the Y half of the bounds guard is not rejecting", got)
			}
		})
	}
}

// The mirror of the test above, kept next to it so a guard rewrite that drops
// the X half instead is caught by the same pair.
func TestWarpImgRejectsAnOutOfRangeXEvenWhenYIsInRange(t *testing.T) {
	const w, h = 4, 4
	sentinel := color.RGBA{R: 1, G: 2, B: 3, A: 255}
	inside := color.RGBA{R: 9, G: 9, B: 9, A: 255}

	src := funcImage{
		rect: image.Rect(0, 0, w, h),
		at: func(x, y int) color.Color {
			if x < 0 || x >= w || y < 0 || y >= h {
				return sentinel
			}
			return inside
		},
	}

	for _, dx := range []int{w + 50, w + 1, -1, -50} {
		dst := WarpImg(src, func(x, y int) (int, int) { return dx, y })
		if got := countOpaque(dst); got != 0 {
			t.Errorf("displacement (%d, y) produced %d opaque pixels, want 0 — WarpImg read outside the source rectangle on the X axis", dx, got)
		}
	}
}

func TestWarpImgEmptySourceProducesEmptyDestination(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 0, 0))
	called := false
	dst := WarpImg(src, func(x, y int) (int, int) { called = true; return x, y })

	if called {
		t.Error("displacement was called for an empty source")
	}
	if !dst.Bounds().Empty() {
		t.Errorf("dst bounds = %v, want empty", dst.Bounds())
	}
}

// ---------------------------------------------------------------------------
// DrawTriangle — the captcha's "cut a triangle out of the image and paste it
// somewhere else" primitive (core/server/middleware.go:271).
//
// Signature: DrawTriangle(blacklist, src, dst, x, y, size, shift)
//   for i in [0,size), for j in [0,size-i):
//     if !blacklist[(x+i, y+j)]:
//        dst.Set(x+i+shift, y+j, src.At(x+i, y+j))   // paste, SHIFTED
//        src.Set(x+i, y+j, transparent)              // erase, UNSHIFTED
//        blacklist[(x+i, y+j)] = true                // mark, UNSHIFTED
// ---------------------------------------------------------------------------

func TestDrawTriangleCopiesShiftsAndErases(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 20, 20))
	dst := image.NewRGBA(image.Rect(0, 0, 20, 20))
	fillRGBA(src, red)

	const x, y, size, shift = 2, 3, 4, 5
	blacklist := DrawTriangle(map[[2]int]bool{}, src, dst, x, y, size, shift)

	// A right triangle of side `size` covers size*(size+1)/2 pixels.
	wantPixels := size * (size + 1) / 2
	if len(blacklist) != wantPixels {
		t.Errorf("blacklist has %d entries, want %d", len(blacklist), wantPixels)
	}
	if got := countOpaque(dst); got != wantPixels {
		t.Errorf("dst has %d opaque pixels, want %d", got, wantPixels)
	}
	if got, want := countOpaque(src), 20*20-wantPixels; got != want {
		t.Errorf("src has %d opaque pixels left, want %d", got, want)
	}

	for i := 0; i < size; i++ {
		for j := 0; j < size-i; j++ {
			// Pasted at the SHIFTED coordinate.
			if got := dst.RGBAAt(x+i+shift, y+j); got != red {
				t.Errorf("dst(%d,%d) = %v, want %v", x+i+shift, y+j, got, red)
			}
			// Erased at the UNSHIFTED coordinate.
			if got := src.RGBAAt(x+i, y+j); got != transparent {
				t.Errorf("src(%d,%d) = %v, want transparent (erased)", x+i, y+j, got)
			}
			// Blacklisted at the UNSHIFTED coordinate.
			if !blacklist[[2]int{x + i, y + j}] {
				t.Errorf("blacklist is missing (%d,%d)", x+i, y+j)
			}
			// The shifted coordinate is NOT blacklisted, which is what lets a
			// later triangle overwrite a region already pasted into dst.
			if blacklist[[2]int{x + i + shift, y + j}] {
				t.Errorf("blacklist unexpectedly contains the shifted coordinate (%d,%d)", x+i+shift, y+j)
			}
		}
	}

	// Nothing outside the triangle was touched in either image.
	if got := dst.RGBAAt(x+shift+size, y); got != transparent {
		t.Errorf("dst outside the triangle was written: %v", got)
	}
	if got := src.RGBAAt(x+size, y); got != red {
		t.Errorf("src outside the triangle was erased: %v", got)
	}
}

func TestDrawTriangleReturnsTheSameMapItWasGiven(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 10, 10))
	dst := image.NewRGBA(image.Rect(0, 0, 10, 10))
	fillRGBA(src, red)

	in := map[[2]int]bool{}
	out := DrawTriangle(in, src, dst, 0, 0, 3, 1)

	if len(in) != len(out) {
		t.Fatalf("the passed map has %d entries but the returned map has %d — DrawTriangle is supposed to mutate in place", len(in), len(out))
	}
	for k := range out {
		if !in[k] {
			t.Fatalf("returned map is not the same map: %v missing from the input map", k)
		}
	}
}

// BUG (a later wave flips this): src pixels are erased UNCONDITIONALLY, even
// when the corresponding dst.Set landed outside the destination rectangle and
// was silently discarded. image.RGBA.Set is a no-op out of bounds, so any
// triangle whose shifted destination runs off the right edge of dst loses those
// pixels permanently: gone from src, never in dst, and blacklisted so no later
// call can recover them. This is the mechanism behind the audit's "~79% of
// generated captchas are unsolvable" finding — the answer glyphs are erased
// from the image the user sees without appearing in the mask. When a wave makes
// the erase conditional on the paste succeeding (or clamps the shift), the
// counts below change.
func TestDrawTriangleErasesSourcePixelsThatNeverReachTheDestination(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 10, 10))
	dst := image.NewRGBA(image.Rect(0, 0, 10, 10))
	fillRGBA(src, red)

	// x=7, size=3 -> columns 7,8,9. shift=5 -> destination columns 12,13,14,
	// all past dst's right edge (10). Every paste is discarded.
	const x, y, size, shift = 7, 0, 3, 5
	blacklist := DrawTriangle(map[[2]int]bool{}, src, dst, x, y, size, shift)

	wantPixels := size * (size + 1) / 2 // 6
	if len(blacklist) != wantPixels {
		t.Fatalf("blacklist has %d entries, want %d", len(blacklist), wantPixels)
	}
	if got := countOpaque(dst); got != 0 {
		t.Errorf("dst has %d opaque pixels, want 0 — every paste should have fallen outside dst", got)
	}
	if got, want := countOpaque(src), 10*10-wantPixels; got != want {
		t.Errorf("src has %d opaque pixels, want %d — the pixels were erased even though nothing was pasted", got, want)
	}

	// Explicitly: the data is gone from both images.
	for i := 0; i < size; i++ {
		for j := 0; j < size-i; j++ {
			if got := src.RGBAAt(x+i, y+j); got != transparent {
				t.Errorf("src(%d,%d) = %v, want transparent", x+i, y+j, got)
			}
		}
	}
}

// BUG (a later wave flips this): the blacklist is keyed on the UNSHIFTED source
// coordinate, so a second DrawTriangle over the same source region is a
// complete no-op no matter what shift it is given. In the captcha the shift is
// random per triangle (middleware.go:271), so two triangles that happen to
// overlap silently drop the second one's contribution entirely — the region is
// erased from src by the first call and never pasted anywhere for the second.
func TestDrawTriangleSecondPassOverTheSameRegionCopiesNothing(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 20, 20))
	dst := image.NewRGBA(image.Rect(0, 0, 20, 20))
	fillRGBA(src, red)

	blacklist := map[[2]int]bool{}
	blacklist = DrawTriangle(blacklist, src, dst, 2, 2, 4, 5)

	afterFirstDst := countOpaque(dst)
	afterFirstSrc := countOpaque(src)
	entriesAfterFirst := len(blacklist)

	// Same region, a different shift.
	blacklist = DrawTriangle(blacklist, src, dst, 2, 2, 4, 9)

	if len(blacklist) != entriesAfterFirst {
		t.Errorf("blacklist grew from %d to %d on the second pass, want no growth", entriesAfterFirst, len(blacklist))
	}
	if got := countOpaque(dst); got != afterFirstDst {
		t.Errorf("dst gained pixels on the second pass: %d -> %d, want unchanged", afterFirstDst, got)
	}
	if got := countOpaque(src); got != afterFirstSrc {
		t.Errorf("src changed on the second pass: %d -> %d, want unchanged", afterFirstSrc, got)
	}
	// Nothing was written at the second shift's destination.
	if got := dst.RGBAAt(2+9, 2); got != transparent {
		t.Errorf("dst(%d,%d) = %v, want transparent — the second pass was suppressed by the blacklist", 2+9, 2, got)
	}
}

// A partially overlapping second triangle copies only its non-overlapping part.
// Pins the partial-suppression behaviour, which is what actually happens with
// the random placement the captcha uses.
func TestDrawTrianglePartialOverlapCopiesOnlyTheNewPixels(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 30, 30))
	dst := image.NewRGBA(image.Rect(0, 0, 30, 30))
	fillRGBA(src, red)

	blacklist := map[[2]int]bool{}
	blacklist = DrawTriangle(blacklist, src, dst, 5, 5, 4, 10) // 10 pixels
	if len(blacklist) != 10 {
		t.Fatalf("first triangle marked %d pixels, want 10", len(blacklist))
	}

	// Second triangle at (6,5) size 4 -> 10 pixels, of which 6 overlap the
	// first (columns 6,7,8 rows within both triangles).
	blacklist = DrawTriangle(blacklist, src, dst, 6, 5, 4, 10)

	newlyMarked := len(blacklist) - 10
	if newlyMarked <= 0 || newlyMarked >= 10 {
		t.Fatalf("second triangle newly marked %d pixels; expected a partial overlap (0 < n < 10)", newlyMarked)
	}
	if got := countOpaque(dst); got != len(blacklist) {
		t.Errorf("dst has %d opaque pixels but the blacklist has %d entries; they should match when every paste lands inside dst", countOpaque(dst), len(blacklist))
	}
}

func TestDrawTriangleEdgeCasesDoNotPanic(t *testing.T) {
	tests := []struct {
		name              string
		x, y, size, shift int
	}{
		{name: "zero size is a no-op", x: 5, y: 5, size: 0, shift: 3},
		{name: "negative size is a no-op", x: 5, y: 5, size: -4, shift: 3},
		{name: "size one is a single pixel", x: 5, y: 5, size: 1, shift: 0},
		{name: "origin", x: 0, y: 0, size: 3, shift: 0},
		{name: "negative origin", x: -5, y: -5, size: 4, shift: 2},
		{name: "far negative origin, entirely outside", x: -1000, y: -1000, size: 4, shift: 2},
		{name: "origin past the far corner", x: 1000, y: 1000, size: 4, shift: 2},
		{name: "negative shift moves the paste left", x: 8, y: 2, size: 3, shift: -6},
		{name: "negative shift pushes the paste off the left edge", x: 1, y: 2, size: 3, shift: -50},
		{name: "size larger than the image", x: 0, y: 0, size: 100, shift: 1},
		{name: "shift larger than the image", x: 0, y: 0, size: 3, shift: 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := image.NewRGBA(image.Rect(0, 0, 16, 16))
			dst := image.NewRGBA(image.Rect(0, 0, 16, 16))
			fillRGBA(src, red)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DrawTriangle(x=%d, y=%d, size=%d, shift=%d) panicked: %v", tt.x, tt.y, tt.size, tt.shift, r)
				}
			}()

			blacklist := DrawTriangle(map[[2]int]bool{}, src, dst, tt.x, tt.y, tt.size, tt.shift)

			if tt.size <= 0 {
				if len(blacklist) != 0 {
					t.Errorf("size %d marked %d pixels, want 0", tt.size, len(blacklist))
				}
				if got := countOpaque(dst); got != 0 {
					t.Errorf("size %d wrote %d dst pixels, want 0", tt.size, got)
				}
				if got := countOpaque(src); got != 16*16 {
					t.Errorf("size %d erased src pixels: %d remain, want 256", tt.size, got)
				}
			} else if want := tt.size * (tt.size + 1) / 2; len(blacklist) != want {
				// The blacklist is marked for every triangle coordinate
				// regardless of whether it lies inside either image — it is a
				// pure coordinate set, not a pixel set.
				t.Errorf("size %d marked %d pixels, want %d", tt.size, len(blacklist), want)
			}
			if src.Bounds() != image.Rect(0, 0, 16, 16) || dst.Bounds() != image.Rect(0, 0, 16, 16) {
				t.Errorf("bounds changed: src=%v dst=%v", src.Bounds(), dst.Bounds())
			}
		})
	}
}

// Pins today's contract: a nil blacklist map panics on the first write. Reads
// from a nil map are legal, so the panic happens at the assignment, not the
// lookup — meaning a zero-size triangle with a nil map does NOT panic. Both
// halves are pinned so a wave that adds a lazy-init shows up as a diff.
func TestDrawTriangleNilBlacklistPanicsOnlyWhenItWrites(t *testing.T) {
	t.Run("nil map with a non-empty triangle panics", func(t *testing.T) {
		src := image.NewRGBA(image.Rect(0, 0, 8, 8))
		dst := image.NewRGBA(image.Rect(0, 0, 8, 8))
		fillRGBA(src, red)

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("DrawTriangle with a nil blacklist did not panic; today it assigns into a nil map")
			}
		}()
		_ = DrawTriangle(nil, src, dst, 0, 0, 2, 1)
	})

	t.Run("nil map with a zero-size triangle does not panic", func(t *testing.T) {
		src := image.NewRGBA(image.Rect(0, 0, 8, 8))
		dst := image.NewRGBA(image.Rect(0, 0, 8, 8))

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DrawTriangle(nil, size=0) panicked: %v", r)
			}
		}()
		got := DrawTriangle(nil, src, dst, 0, 0, 0, 1)
		if got != nil {
			t.Errorf("returned map = %v, want nil (the nil map is passed straight back)", got)
		}
	})
}

// src and dst may be the same image. Pins what happens then: the paste is
// written first and the erase second, so with shift != 0 the triangle is moved
// within one image, and with shift == 0 the pixel is written and then
// immediately erased — a pure delete.
func TestDrawTriangleSameSourceAndDestination(t *testing.T) {
	t.Run("shift zero erases everything it writes", func(t *testing.T) {
		img := image.NewRGBA(image.Rect(0, 0, 12, 12))
		fillRGBA(img, red)

		DrawTriangle(map[[2]int]bool{}, img, img, 2, 2, 3, 0)

		for i := 0; i < 3; i++ {
			for j := 0; j < 3-i; j++ {
				if got := img.RGBAAt(2+i, 2+j); got != transparent {
					t.Errorf("img(%d,%d) = %v, want transparent", 2+i, 2+j, got)
				}
			}
		}
	})

	t.Run("non-zero shift relocates the pixels within the image", func(t *testing.T) {
		img := image.NewRGBA(image.Rect(0, 0, 12, 12))
		fillRGBA(img, red)

		DrawTriangle(map[[2]int]bool{}, img, img, 0, 0, 2, 6)

		// Destination columns 6,7 are still red (they already were), and the
		// source triangle is erased.
		if got := img.RGBAAt(0, 0); got != transparent {
			t.Errorf("img(0,0) = %v, want transparent (erased)", got)
		}
		if got := img.RGBAAt(6, 0); got != red {
			t.Errorf("img(6,0) = %v, want %v", got, red)
		}
	})
}
