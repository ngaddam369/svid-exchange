package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketName = []byte("policies")

var revocationsBucket = []byte("revocations")

// Store is a BoltDB-backed persistent store for dynamic policies.
// Dynamic policies supplement the YAML file and survive server restarts.
type Store struct {
	db *bolt.DB
}

// OpenStore opens (or creates) the BoltDB file at path and ensures the
// policies bucket exists. Callers must call Close when done.
//
// BoltDB uses MVCC with serializable isolation: each read-write transaction
// (db.Update) sees a consistent snapshot and is the only writer at a time.
// Read-only transactions (db.View) run concurrently and never block writes.
// No additional locking is needed around Store method calls.
func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open policy store: %w", err)
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketName); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(revocationsBucket)
		return err
	}); err != nil {
		return nil, errors.Join(fmt.Errorf("init policy bucket: %w", err), db.Close())
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Save creates or replaces the policy with the given name.
func (s *Store) Save(p Policy) error {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put([]byte(p.Name), data)
	})
}

// Delete removes the policy with the given name.
// It is not an error to delete a name that does not exist.
func (s *Store) Delete(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Delete([]byte(name))
	})
}

// List returns all dynamic policies in key-sorted order.
func (s *Store) List() ([]Policy, error) {
	var out []Policy
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).ForEach(func(_, v []byte) error {
			var p Policy
			if err := json.Unmarshal(v, &p); err != nil {
				return fmt.Errorf("unmarshal policy: %w", err)
			}
			out = append(out, p)
			return nil
		})
	})
	return out, err
}

// RevokedEntry holds a persisted revocation record.
type RevokedEntry struct {
	JTI       string
	ExpiresAt int64 // Unix timestamp
}

// SaveRevocation persists a revoked JTI with its natural expiry timestamp.
func (s *Store) SaveRevocation(jti string, expiresAt int64) error {
	data, err := json.Marshal(expiresAt)
	if err != nil {
		return fmt.Errorf("marshal revocation: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(revocationsBucket).Put([]byte(jti), data)
	})
}

// DeleteRevocation removes a revocation entry from the persistent store.
// It is not an error to delete a JTI that does not exist.
func (s *Store) DeleteRevocation(jti string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(revocationsBucket).Delete([]byte(jti))
	})
}

// ListRevocations returns all persisted revocation entries.
func (s *Store) ListRevocations() ([]RevokedEntry, error) {
	var out []RevokedEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(revocationsBucket).ForEach(func(k, v []byte) error {
			var expiresAt int64
			if err := json.Unmarshal(v, &expiresAt); err != nil {
				return fmt.Errorf("unmarshal revocation: %w", err)
			}
			out = append(out, RevokedEntry{JTI: string(k), ExpiresAt: expiresAt})
			return nil
		})
	})
	return out, err
}
