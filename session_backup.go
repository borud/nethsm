package nethsm

import (
	"errors"
	"os"

	"github.com/borud/nethsm/api"
)

// Backup initiates backup.
func (s *Session) Backup() (*os.File, error) {
	f, res, err := s.client.SystemBackupPost(s.authCtx).Execute()
	defer closeBody(res)
	if err != nil {
		return nil, errors.Join(err, asError(res))
	}
	return f, nil
}

// Restore backup from file.
func (s *Session) Restore(backupPass string, backupFile *os.File) error {
	resp, err := s.client.SystemRestorePost(s.authCtx).
		Arguments(api.RestoreRequestArguments{
			BackupPassphrase: &backupPass,
		}).
		BackupFile(backupFile).
		Execute()
	defer closeBody(resp)
	if err != nil {
		return errors.Join(err, asError(resp))
	}
	return nil
}

// SetBackupPassword sets the backup password.  If no password was set then
// provide the empty string for currentPass.
func (s *Session) SetBackupPassword(newPass, currentPass string) error {
	resp, err := s.client.ConfigBackupPassphrasePut(s.authCtx).BackupPassphraseConfig(api.BackupPassphraseConfig{
		NewPassphrase:     newPass,
		CurrentPassphrase: currentPass,
	}).Execute()
	defer closeBody(resp)

	if err != nil {
		return errors.Join(err, asError(resp))
	}
	return nil
}
