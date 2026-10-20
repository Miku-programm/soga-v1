package service

import (
	"os"
	"reflect"
	"syscall"
	"testing"
)

type recordedLifecycle struct{ calls []string }

func (r *recordedLifecycle) InitLinux() { r.calls = append(r.calls, "init") }
func (r *recordedLifecycle) InitUnix()  { r.calls = append(r.calls, "cleanup") }

func TestSignalReloadThenTerminate(t *testing.T) {
	signals := make(chan os.Signal, 3)
	signals <- syscall.Signal(10)
	signals <- syscall.Signal(10)
	signals <- syscall.Signal(15)
	instance := &recordedLifecycle{}
	RunSignals(instance, signals)
	want := []string{"init", "cleanup", "init", "cleanup", "init", "cleanup"}
	if !reflect.DeepEqual(instance.calls, want) {
		t.Fatalf("calls = %v, want %v", instance.calls, want)
	}
}

func TestSignalOtherAndClosedChannelStop(t *testing.T) {
	for _, number := range []int{1, 2, 9, 15, 0, 99} {
		instance := &recordedLifecycle{}
		signals := make(chan os.Signal, 1)
		if number == 0 {
			close(signals)
		} else {
			signals <- syscall.Signal(number)
		}
		RunSignals(instance, signals)
		if !reflect.DeepEqual(instance.calls, []string{"init", "cleanup"}) {
			t.Fatalf("signal %d: calls = %v", number, instance.calls)
		}
	}
}
