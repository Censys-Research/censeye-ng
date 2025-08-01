package cache

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var CACHE_MAGIC = []byte("CENS")

type Cachable interface {
	Hash() string
	Bytes() []byte
}

type CacheKey interface {
	Hash() string
}

type Entry struct {
	timestamp int64
	data      []byte
}

type GenericCachable[T any] struct {
	Key   CacheKey
	Value T
	Enc   func(T) []byte
}

type Manager struct {
	dir         string
	expireAfter time.Duration
	sync.Mutex
}

func (e *Entry) Age() time.Duration   { return time.Since(time.Unix(e.timestamp, 0)) }
func (e *Entry) CreatedAt() time.Time { return time.Unix(e.timestamp, 0) }
func (e *Entry) Bytes() []byte        { return e.data }

func (g *GenericCachable[T]) Hash() string  { return g.Key.Hash() }
func (g *GenericCachable[T]) Bytes() []byte { return g.Enc(g.Value) }

func NewManager(dir string, expire time.Duration) *Manager {
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}

	return &Manager{dir: dir, expireAfter: expire}
}

func (m *Manager) Save(obj Cachable) (string, error) {
	m.Lock()
	defer m.Unlock()

	sum := md5Hash(obj.Hash())
	dir := filepath.Join(m.dir, sum[0:2], sum[2:4], sum[4:6])
	fn := filepath.Join(dir, sum)
	dat := obj.Bytes()

	log.Debugf("saving cache entry for %s to %s", obj.Hash(), fn)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	var buf bytes.Buffer

	if _, err := buf.Write(CACHE_MAGIC); err != nil {
		return "", fmt.Errorf("write magic: %w", err)
	}

	timestamp := uint64(time.Now().Unix())
	if err := binary.Write(&buf, binary.BigEndian, timestamp); err != nil {
		return "", fmt.Errorf("write timestamp: %w", err)
	}

	if _, err := buf.Write(dat); err != nil {
		return "", fmt.Errorf("write payload: %w", err)
	}

	if err := os.WriteFile(fn, buf.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}

	return fn, nil
}

func (m *Manager) Load(obj Cachable) (*Entry, error) {
	m.Lock()
	defer m.Unlock()

	sum := md5Hash(obj.Hash())
	fn := filepath.Join(m.dir, sum[0:2], sum[2:4], sum[4:6], sum)

	log.Debugf("loading cache entry for %s from %s", obj.Hash(), fn)

	dat, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	if len(dat) < 12 {
		return nil, fmt.Errorf("file too short: %d bytes", len(dat))
	}

	if !bytes.Equal(dat[:4], CACHE_MAGIC) {
		return nil, fmt.Errorf("invalid magic: %q", dat[:4])
	}

	ts := int64(binary.BigEndian.Uint64(dat[4:12]))
	ret := &Entry{
		timestamp: ts,
		data:      dat[12:],
	}

	log.Debugf("loaded cache entry for %s, created at %s", obj.Hash(), ret.CreatedAt())
	if ret.Age() > m.expireAfter {
		log.Debugf("cache entry for %s is expired (age: %s)", obj.Hash(), ret.Age())
		return nil, fmt.Errorf("cache entry expired")
	}

	return ret, nil
}

func md5Hash(input string) string {
	sum := md5.Sum([]byte(input))
	return hex.EncodeToString(sum[:])
}
