package service

import (
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/robfig/cron/v3"
)

type recordedJob struct {
	spec   string
	index  int
	visits *[]int
	runs   atomic.Int32
}

func (j *recordedJob) Cron() string {
	*j.visits = append(*j.visits, j.index)
	return j.spec
}
func (j *recordedJob) Run() { j.runs.Add(1) }

func TestRegisterStopsAtFirstErrorAndKeepsEarlierEntries(t *testing.T) {
	var visited []int
	first := &recordedJob{spec: "@every 1h", index: 1, visits: &visited}
	second := &recordedJob{spec: "invalid schedule", index: 2, visits: &visited}
	third := &recordedJob{spec: "@every 2h", index: 3, visits: &visited}
	scheduler := cron.New()
	jobs := Jobs{Scheduler: scheduler, Tasks: []Job{first, second, third}}
	if err := jobs.Register(); err == nil {
		t.Fatal("expected cron parser error")
	}
	if !reflect.DeepEqual(visited, []int{1, 2}) || len(jobs.IDs) != 1 || len(scheduler.Entries()) != 1 {
		t.Fatal(visited, jobs.IDs, scheduler.Entries())
	}
	if first.runs.Load() != 0 {
		t.Fatal("registration executed the business task")
	}
}

func TestRegisterAgainDoesNotRemoveOldEntries(t *testing.T) {
	var visited []int
	task := &recordedJob{spec: "@every 1h", visits: &visited}
	jobs := Jobs{Scheduler: cron.New(), Tasks: []Job{task}}
	if err := jobs.Register(); err != nil {
		t.Fatal(err)
	}
	old := jobs.IDs[0]
	if err := jobs.Register(); err != nil {
		t.Fatal(err)
	}
	if len(jobs.IDs) != 1 || jobs.IDs[0] == old || len(jobs.Scheduler.Entries()) != 2 {
		t.Fatal(jobs.IDs, jobs.Scheduler.Entries())
	}
}

func TestEmptyRegistrationClearsIDsWithoutRemovingJobs(t *testing.T) {
	var visited []int
	jobs := Jobs{Scheduler: cron.New(), Tasks: []Job{&recordedJob{spec: "@every 1h", visits: &visited}}}
	if err := jobs.Register(); err != nil {
		t.Fatal(err)
	}
	jobs.Tasks = nil
	if err := jobs.Register(); err != nil {
		t.Fatal(err)
	}
	if jobs.IDs == nil || len(jobs.IDs) != 0 || len(jobs.Scheduler.Entries()) != 1 {
		t.Fatal(jobs.IDs, jobs.Scheduler.Entries())
	}
}

func TestShutdownCancelsBeforeRemovalAndRetainsIDs(t *testing.T) {
	var visited []int
	jobs := Jobs{Scheduler: cron.New(), Tasks: []Job{
		&recordedJob{spec: "@every 1h", index: 1, visits: &visited},
		&recordedJob{spec: "@every 2h", index: 2, visits: &visited},
	}}
	if err := jobs.Register(); err != nil {
		t.Fatal(err)
	}
	ids := append([]cron.EntryID(nil), jobs.IDs...)
	cancelled := false
	jobs.Cancel = func() {
		if len(jobs.Scheduler.Entries()) != 2 {
			t.Fatal("entries removed before cancellation")
		}
		cancelled = true
	}
	jobs.Shutdown()
	if !cancelled || len(jobs.Scheduler.Entries()) != 0 || !reflect.DeepEqual(jobs.IDs, ids) {
		t.Fatal(cancelled, jobs.Scheduler.Entries(), jobs.IDs)
	}
}

func TestShutdownWithNoEntriesStillCancels(t *testing.T) {
	called := false
	jobs := Jobs{Cancel: func() { called = true }}
	jobs.Shutdown()
	if !called {
		t.Fatal("cancel was skipped for empty ID list")
	}
}
