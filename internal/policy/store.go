package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketName = []byte("policies")

// Store is a BoltDB-backed persistent store for dynamic policies.
// Dynamic policies supplement the YAML file and survive server restarts.
type Store struct {
	db *bolt.DB
}

// OpenStore opens (or creates) the BoltDB file at path and ensures the
// policies bucket exists. Callers must call Close when done.
func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open policy store: %w", err)
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
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
