package main

import "testing"

func TestScrollLockIgnoresAClampedFollower(t *testing.T) {
	// Input scrolled down to 100. Output content can only reach 40, so its
	// layout clamps the shared offset. That clamp must not pull input back.
	got := reconcileScroll(100, 100, 100, 400, 100, 40, 40)
	if got != 100 {
		t.Fatalf("clamped follower changed the shared offset to %d", got)
	}
}

func TestScrollLockFollowsThePaneThatMoved(t *testing.T) {
	got := reconcileScroll(10, 10, 55, 400, 10, 10, 400)
	if got != 55 {
		t.Fatalf("input scroll: got %d", got)
	}
	got = reconcileScroll(80, 80, 80, 400, 80, 20, 400)
	if got != 20 {
		t.Fatalf("output scroll: got %d", got)
	}
}

func TestUserScrollClampsToThePane(t *testing.T) {
	moved, value := userScroll(10, 500, 40)
	if !moved || value != 40 {
		t.Fatalf("down: moved=%v value=%d", moved, value)
	}
	moved, value = userScroll(100, 40, 40)
	if moved {
		t.Fatalf("clamp was treated as a user scroll to %d", value)
	}
}
