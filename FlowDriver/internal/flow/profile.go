package flow

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/NullLatency/flow-driver/internal/storage"
	"github.com/NullLatency/flow-driver/internal/transport"
)

const MaxProfileSize = 65536

type Profile struct {
	FolderID     string `json:"folder_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"key"`
	PollMS       int    `json:"poll_ms,omitempty"`
	FlushMS      int    `json:"flush_ms,omitempty"`
	secret       []byte
}

var folderID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

func ParseProfile(data []byte) (Profile, error) {
	var profile Profile
	invalid := errors.New("invalid FlowDriver profile")
	if len(data) > MaxProfileSize {
		return profile, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&profile) != nil || decoder.Decode(new(any)) != io.EOF ||
		!folderID.MatchString(profile.FolderID) || profile.ClientID == "" || profile.RefreshToken == "" {
		return Profile{}, invalid
	}
	secret, err := base64.StdEncoding.DecodeString(profile.Key)
	if err != nil || len(secret) != 32 {
		return Profile{}, invalid
	}
	if profile.PollMS == 0 {
		profile.PollMS = 750
	}
	if profile.FlushMS == 0 {
		profile.FlushMS = 400
	}
	if profile.PollMS < 250 || profile.PollMS > 3000 || profile.FlushMS < 150 || profile.FlushMS > 1500 {
		return Profile{}, invalid
	}
	profile.secret = secret
	return profile, nil
}

func (p Profile) Backend() (storage.Backend, error) {
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	backend := storage.NewGoogleBackend(client, p.FolderID, p.ClientID, p.ClientSecret, p.RefreshToken)
	return storage.Encrypted(backend, p.secret)
}

func (p Profile) Engine(backend storage.Backend, client bool, id string) *transport.Engine {
	engine := transport.NewEngine(backend, client, id)
	engine.SetPollRate(p.PollMS)
	engine.SetFlushRate(p.FlushMS)
	return engine
}
