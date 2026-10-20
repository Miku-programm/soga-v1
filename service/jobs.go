// Package service contains recovered lifecycle components. It does not supply
// the unrecovered panel clients, protocol servers, or periodic business jobs.
package service

import (
	"context"

	"github.com/robfig/cron/v3"
)

// Job is the original two-method shape recovered from interface RTTI at
// 0x35e0780: Cron() string and Run(). The first name is Cron, not Schedule.
type Job interface {
	Cron() string
	Run()
}

// Jobs holds the receiver fields used by the registration method:
// scheduler +0x18, task slice +0x20, entry IDs +0x38.
// Field names and this narrow public type are reconstruction API choices.
// Like the original method, registration expects an initialized scheduler and
// is not synchronized against concurrent changes to its own slices.
type Jobs struct {
	Cancel    context.CancelFunc
	Scheduler *cron.Cron
	Tasks     []Job
	IDs       []cron.EntryID
}

// Shutdown reconstructs the reduced normal path of InitUnix at 0x1fb6400:
// invoke the cancellation function (0x1fb7b71), then Remove each stored ID
// in slice order (0x1fb7768). It does not call Cron.Stop or explicitly wait for
// running jobs, and it leaves IDs intact. Cancel must be initialized by the caller.
func (j *Jobs) Shutdown() {
	j.Cancel()
	for _, id := range j.IDs {
		j.Scheduler.Remove(id)
	}
}

// Register reconstructs CbO_7wp3B.(*M0mmPxPJsa).vVeTh4DwS at 0x1f9a7c0.
// It resets the tracked IDs, calls Cron for each task in order, then AddJob.
// The first scheduling error is returned without rolling back previous jobs.
// Resetting IDs does not remove jobs from a previous Register call.
// Register does not start the cron scheduler.
func (j *Jobs) Register() error {
	j.IDs = make([]cron.EntryID, 0)
	for _, task := range j.Tasks {
		id, err := j.Scheduler.AddJob(task.Cron(), task)
		if err != nil {
			return err
		}
		j.IDs = append(j.IDs, id)
	}
	return nil
}
