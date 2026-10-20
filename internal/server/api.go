package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"git.itknecht.de/sugras/meles/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func validationError(errs map[string]string) error {
	var parts []string
	for field, msg := range errs {
		parts = append(parts, field+": "+msg)
	}
	return errors.New(strings.Join(parts, "; "))
}

func (s *Server) apiListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans(r.Context())
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	if scans == nil {
		scans = []store.Scan{}
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) apiCreateScan(w http.ResponseWriter, r *http.Request) {
	var in scanInput
	if err := decodeJSON(r, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	if errs := in.validate(); len(errs) > 0 {
		writeJSONError(w, http.StatusBadRequest, validationError(errs))
		return
	}
	sc := &store.Scan{}
	in.apply(sc)
	if err := s.store.CreateScan(r.Context(), sc); err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	s.syncSchedule(r)
	writeJSON(w, http.StatusCreated, sc)
}

func (s *Server) apiGetScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeJSONError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	sc, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) apiUpdateScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeJSONError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	sc, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	var in scanInput
	if err := decodeJSON(r, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	if errs := in.validate(); len(errs) > 0 {
		writeJSONError(w, http.StatusBadRequest, validationError(errs))
		return
	}
	in.apply(sc)
	if err := s.store.UpdateScan(r.Context(), sc); err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	s.syncSchedule(r)
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) apiDeleteScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeJSONError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	if err := s.store.DeleteScan(r.Context(), id); err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	s.syncSchedule(r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiRunScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeJSONError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	sc, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	run, err := s.runner.Enqueue(r.Context(), sc, sc.ImageRef, sc.Platforms, store.TriggerAPI)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) apiListRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.RunFilter{Status: q.Get("status"), ImageRef: q.Get("image"), Limit: 100}
	if id, err := strconv.ParseInt(q.Get("scan"), 10, 64); err == nil {
		f.ScanID = id
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 1000 {
		f.Limit = n
	}
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n >= 0 {
		f.Offset = n
	}
	runs, err := s.store.ListRuns(r.Context(), f)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	if runs == nil {
		runs = []store.Run{}
	}
	writeJSON(w, http.StatusOK, runs)
}

func (s *Server) apiCreateRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ImageRef  string `json:"imageRef"`
		Platforms string `json:"platforms"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	in.ImageRef = strings.TrimSpace(in.ImageRef)
	if in.Platforms == "" {
		in.Platforms = "all"
	}
	if err := validateRun(in.ImageRef, in.Platforms); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	run, err := s.runner.Enqueue(r.Context(), nil, in.ImageRef, in.Platforms, store.TriggerAPI)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) apiGetRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeJSONError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	run, err := s.store.GetRun(r.Context(), id)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}
