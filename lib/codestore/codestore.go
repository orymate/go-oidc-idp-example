package codestore

import (
	"errors"
	"time"

	"github.com/oklog/ulid/v2"
)

type code struct {
	ID       ulid.ULID
	id_token string
}

type CodeStore struct {
	codes map[string]code
	ttl   time.Duration
}

func New() *CodeStore {
	return &CodeStore{
		codes: map[string]code{},
		ttl:   time.Minute,
	}
}

func (s *CodeStore) CleanUp() {
	if s.ttl == 0 {
		return
	}
	for k, v := range s.codes {
		if ulid.Time(v.ID.Time()).Before(time.Now().Add(-s.ttl)) {
			delete(s.codes, k)
		}
	}
}

func (s *CodeStore) Create(id_token string) string {
	s.CleanUp()
	code := code{
		ID:       ulid.Make(),
		id_token: id_token,
	}
	s.codes[code.ID.String()] = code

	return code.ID.String()
}

func (s *CodeStore) Get(code string) (string, error) {
	session, ok := s.codes[code]
	if !ok {
		return "", errors.New("code not found")
	}

	return session.id_token, nil
}

func (s *CodeStore) Pop(code string) (id_token string, err error) {
	id_token, err = s.Get(code)
	if err == nil {
		delete(s.codes, code)
	}
	return
}

func (s *CodeStore) Delete(code string) {
	delete(s.codes, code)
}
