package main

// TODO: Errors from DB calls for user not exist and (vs) item not exist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	logpkg "log"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	chi "github.com/go-chi/chi/v5"
	_ "github.com/go-chi/chi/v5/middleware"
	jwtauth "github.com/go-chi/jwtauth/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtCookieName = "journalog-jwt"
	userIdJWTName = "userId"

	statusISE = http.StatusInternalServerError
	iseText   = "internal server error"
	statusBR  = http.StatusBadRequest
	statusUA  = http.StatusUnauthorized
)

var (
	errInvalidCredentials = fmt.Errorf("invalid credentials")
	errUserNotExist       = fmt.Errorf("user not exist")
	errUserExists         = fmt.Errorf("user already exists")
	errLogNotExist        = fmt.Errorf("log not exist")
	errJournalNotExist    = fmt.Errorf("journal doesn't exist")
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8000", "Address to run on")
	dbPath := flag.String("db", "journalog.db", "Path to database")
	journalsDir := flag.String(
		"journals-dir", "./journals", "Journals directory",
	)
	flag.Parse()

	jwtSecret := os.Getenv("JOURNALOG_JWT_SECRET")
	if jwtSecret == "" {
		logpkg.Fatal("JOURNALOG_JWT_SECRET is empty/not set")
	}
	s, err := newServer(*dbPath, jwtSecret, *journalsDir)
	if err != nil {
		logpkg.Fatal(err)
	}

	r := chi.NewMux()
	// Other
	// TODO: Register vs new client
	r.Post("/login", s.LoginHandler)
	r.Post("/users", s.NewUserHandler)

	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verify(
			s.tokenAuth,
			jwtauth.TokenFromHeader,
			func(r *http.Request) string {
				cookie, err := r.Cookie(jwtCookieName)
				if err != nil {
					return ""
				}
				return cookie.Value
			},
		))
		r.Post("/logout", s.LogoutHandler)
		// Users
		r.Get("/users", s.GetUserHandler)
		r.Delete("/users", s.DeleteUserHandler)

		// Logs
		r.Get("/logs", s.GetLogsHandler)
		r.Get("/logs/{id}", s.GetLogHandler)
		r.Post("/logs", s.NewLogHandler)
		r.Delete("/logs/{id}", s.DeleteLogHandler)

		// Journals
		r.Get("/journals", s.GetJournalsHandler)
		r.Get("/journals/{id}", s.GetJournalHandler)
		r.Post("/journals", s.NewJournalHandler)
		r.Delete("/journals/{id}", s.DeleteJournalHandler)
	})

	logpkg.Print("Running on ", *addr)
	logpkg.Fatal(http.ListenAndServe(*addr, r))
}

type Server struct {
	tokenAuth   *jwtauth.JWTAuth
	db          *sql.DB
	journalsDir string
}

func newServer(dbPath, jwtSecret, journalsDir string) (*Server, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	return &Server{
		tokenAuth:   jwtauth.New("HS256", []byte(jwtSecret), nil),
		db:          db,
		journalsDir: journalsDir,
	}, nil
}

func sendErrResp(w http.ResponseWriter, r *http.Request, resp *Resp) {
	if wantsHTML(r) {
		w.Write([]byte(resp.Error))
	} else {
		resp.WriteTo(w)
	}
}

func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	email, password, ok := r.BasicAuth()
	if !ok {
		sendErrResp(w, r, newRespErr(statusBR, "missing credentials"))
		return
	}
	id, err := s.checkPassword(email, password)
	if err != nil {
		if errors.Is(err, errUserNotExist) || errors.Is(err, errInvalidCredentials) {
			sendErrResp(w, r, newRespErr(statusUA, "invalid credentials"))
		} else {
			sendErrResp(w, r, newRespErr(statusISE, iseText))
			logpkg.Printf("error checking credentials for email %s: %v", email, err)
		}
		return
	}
	tokStr, err := s.createToken(id)
	if err != nil {
		sendErrResp(w, r, newRespErr(statusISE, iseText))
		logpkg.Printf("error generating token for ID %d: %v", id, err)
		return
	}
	if wantsHTML(r) && acceptsCookies(r) {
		http.SetCookie(
			w,
			&http.Cookie{
				Name:  jwtCookieName,
				Value: tokStr,
			},
		)
	} else {
		newRespOk(tokStr).WriteTo(w)
	}
}

func (s *Server) createToken(userId uint64) (string, error) {
	claims := map[string]any{userIdJWTName: strconv.FormatUint(userId, 10)}
	jwtauth.SetIssuedNow(claims)
	_, tokStr, err := s.tokenAuth.Encode(claims)
	return tokStr, err
}

func (s *Server) checkPassword(email, password string) (uint64, error) {
	row := s.db.QueryRow(
		`SELECT id,password_hash FROM users WHERE email=?`, email,
	)
	id, hash := uint64(0), ""
	if err := row.Scan(&hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, errUserNotExist
		}
		return 0, err
	}
	if !checkPassword(password, hash) {
		return 0, errInvalidCredentials
	}
	return id, nil
}

func (s *Server) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(
		w,
		&http.Cookie{
			Name:   jwtCookieName,
			Value:  "",
			MaxAge: -1,
		},
	)
	if _, ok := userIdFromJWT(r); !ok {
		newRespErr(statusUA, "missing token").WriteTo(w)
	} else {
		if !wantsHTML(r) {
			// Nothing for right now
			newRespOk(nil).WriteTo(w)
		}
	}
}

/* Users */

type User struct {
	Id           uint64 `json:"id,omitempty"`
	Email        string `json:"email,omitempty"`
	passwordHash string
	CreatedAt    int64 `json:"createdAt"`
}

func (s *Server) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	if id, ok := userIdFromJWT(r); !ok {
		newRespErr(http.StatusUnauthorized, "missing token").WriteTo(w)
	} else if user, err := s.getUser(id); err != nil {
		if errors.Is(err, errUserNotExist) {
			newRespErr(statusBR, "user doesn't exist").WriteTo(w)
		} else {
			newRespErr(statusISE, iseText).WriteTo(w)
			logpkg.Printf("Error getting user for : %v", err)
		}
	} else {
		newRespOk(user).WriteTo(w)
	}
}

func (s *Server) getUser(id uint64) (User, error) {
	row := s.db.QueryRow(`SELECT email,created_at FROM users WHERE id=?`, id)
	user := User{Id: id}
	if err := row.Scan(&user.Email, &user.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			err = errUserNotExist
		}
		return User{}, err
	}
	return user, nil
}

func (s *Server) NewUserHandler(w http.ResponseWriter, r *http.Request) {
	_, password, ok := r.BasicAuth()
	if !ok {
		sendErrResp(w, r, newRespErr(statusBR, "missing credentials"))
		return
	}
	user := User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		// TODO: Handle errors
		sendErrResp(w, r, newRespErr(statusBR, "invalid user object"))
		return
	} else if !checkEmail(user.Email) {
		sendErrResp(w, r, newRespErr(statusBR, "invalid credentials"))
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		sendErrResp(w, r, newRespErr(statusBR, "bad credentials"))
		return
	}
	user.passwordHash, user.CreatedAt = hash, time.Now().Unix()
	if err := s.newUser(&user); err != nil {
		if errors.Is(err, errUserExists) {
			sendErrResp(w, r, newRespErr(statusBR, "user with email already exists"))
		} else {
			sendErrResp(w, r, newRespErr(statusISE, iseText))
			logpkg.Printf("error creating user for email %s: %v", user.Email, err)
		}
		return
	}
	journalsPath := filepath.Join(
		s.journalsDir, s.generateJournalsDirPath(user.Id),
	)
	if err := os.MkdirAll(journalsPath, 0750); err != nil {
		sendErrResp(w, r, newRespErr(statusISE, iseText))
		logpkg.Printf("error creating directory for ID %d: %v", user.Id, err)
		return
	}
	tokStr, err := s.createToken(user.Id)
	if err != nil {
		sendErrResp(w, r, newRespErr(statusISE, iseText))
		logpkg.Printf("error generating token for ID %d: %v", user.Id, err)
		return
	}
	if wantsHTML(r) && acceptsCookies(r) {
		http.SetCookie(
			w,
			&http.Cookie{
				Name:  jwtCookieName,
				Value: tokStr,
			},
		)
	} else {
		newRespOk(tokStr).WriteTo(w)
	}
}

func (s *Server) newUser(user *User) error {
	res, err := s.db.Exec(
		`INSERT INTO users(email,password_hash,created_at) VALUES (?,?,?)`,
		user.Email, user.passwordHash, time.Now().Unix(),
	)
	if err != nil {
		if strings.HasPrefix(err.Error(), "UNIQUE constraint failed:") {
			return errUserExists
		}
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	user.Id = uint64(id)
	return nil
}

func (s *Server) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if id, ok := userIdFromJWT(r); !ok {
		newRespErr(http.StatusUnauthorized, "missing token").WriteTo(w)
	} else if err := s.deleteUser(id); err != nil {
		if errors.Is(err, errUserNotExist) {
			newRespErr(statusBR, "user doesn't exist").WriteTo(w)
		} else {
			newRespErr(statusISE, iseText).WriteTo(w)
			logpkg.Printf("Error getting user for : %v", err)
		}
	} else {
		newRespOk(nil).WriteTo(w)
	}
}

func (s *Server) deleteUser(id uint64) error {
	if res, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id); err != nil {
		return err
	} else if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errUserNotExist
	}
	// NOTE: No need to delete logs or journals explicitly since they should
	// cascade
	return os.RemoveAll(
		filepath.Join(s.journalsDir, s.generateJournalsDirPath(id)),
	)
}

/* Logs */

type Log struct {
	Id        uint64 `json:"id,omitempty"`
	UserId    uint64 `json:"userId,omitempty"`
	Timestamp int64  `json:"timestamp"`
	Contents  string `json:"contents"`
	// TODO: What are these? Are they for chains of associated logs?
	/*
	  StartId uint64 `json:"-"`
	  EndId uint64 `json:"-"`
	*/
}

type GetLogsOpts struct {
	Before     int64
	After      int64
	SortByTime bool
	SortDesc   bool
}

// Any error returned from here can be sent directly to the client without
// needing to be changed or logged
func parseGetLogsOpts(r *http.Request) (GetLogsOpts, error) {
	var err error
	opts, query := GetLogsOpts{}, r.URL.Query()
	if beforeStr := query.Get("before"); beforeStr == "" {
	} else if opts.Before, err = strconv.ParseInt(beforeStr, 10, 64); err != nil {
		return opts, fmt.Errorf("invalid `before` value")
	} else if opts.Before < 0 {
		return opts, fmt.Errorf("`before` cannot be negative")
	}

	if afterStr := query.Get("after"); afterStr == "" {
	} else if opts.After, err = strconv.ParseInt(afterStr, 10, 64); err != nil {
		return opts, fmt.Errorf("invalid `after` value")
	} else if opts.After < 0 {
		return opts, fmt.Errorf("`after` cannot be negative")
	}

	if sortTimeStr := query.Get("sort_time"); sortTimeStr == "" {
	} else if opts.SortByTime, err = strconv.ParseBool(sortTimeStr); err != nil {
		return opts, fmt.Errorf("invalid `sort_time` value")
	}

	if sortDescStr := query.Get("time_desc"); sortDescStr == "" {
	} else if opts.SortDesc, err = strconv.ParseBool(sortDescStr); err != nil {
		return opts, fmt.Errorf("invalid `time_desc` value")
	}
	return opts, nil
}

// The returned string, has a leading space (if there was something to add)
func (opts GetLogsOpts) makeQuery() string {
	stmt := ""
	if opts.After != 0 {
		stmt += fmt.Sprint(` AND timestamp > `, opts.After)
	}
	if opts.Before != 0 {
		stmt += fmt.Sprint(` AND timestamp < `, opts.Before)
	}
	sorting := false
	if opts.SortByTime {
		sorting = true
		stmt += ` ORDER BY timestamp`
	}
	if opts.SortDesc {
		if !sorting {
			stmt += ` ORDER BY timestamp`
		}
		stmt += ` DESC`
	}
	return stmt
}

func (s *Server) GetLogsHandler(w http.ResponseWriter, r *http.Request) {
	if opts, err := parseGetLogsOpts(r); err != nil {
		newRespErr(statusBR, err.Error()).WriteTo(w)
	} else if userId, ok := userIdFromJWT(r); !ok {
		newRespErr(http.StatusUnauthorized, "invalid JWT").WriteTo(w)
	} else if logs, err := s.getLogs(userId, opts); err != nil {
		newResp(statusISE, logs, iseText)
		logpkg.Printf("error getting logs for ID %d: %v", userId, err)
	} else {
		newRespOk(logs).WriteTo(w)
	}
}

func (s *Server) getLogs(userId uint64, opts GetLogsOpts) ([]Log, error) {
	stmt := `SELECT id,timestamp,contents FROM logs WHERE user_id=?`
	rows, err := s.db.Query(stmt+opts.makeQuery(), userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []Log
	for rows.Next() {
		log := Log{UserId: userId}
		if e := rows.Scan(&log.Id, &log.Timestamp, &log.Contents); e != nil {
			// Set to first error
			if err != nil {
				err = e
			}
		} else {
			logs = append(logs, log)
		}
	}
	return logs, err
}

func (s *Server) GetLogHandler(w http.ResponseWriter, r *http.Request) {
	if userId, ok := userIdFromJWT(r); !ok {
		newRespErr(http.StatusUnauthorized, "invalid JWT").WriteTo(w)
	} else if logId, ok := idFromReq(r); !ok {
		newRespErr(statusBR, "invalid log id").WriteTo(w)
	} else if log, err := s.getLog(userId, logId); err != nil {
		status, errMsg := 0, ""
		if errors.Is(err, errUserNotExist) {
			status, errMsg = http.StatusUnauthorized, "user doesn't exist"
		} else if errors.Is(err, errLogNotExist) {
			status, errMsg = http.StatusNotFound, "log doesn't exist"
		} else {
			status, errMsg = statusISE, iseText
			logpkg.Printf("error getting log for ID %d: %v", userId, err)
		}
		newRespErr(status, errMsg).WriteTo(w)
	} else {
		newRespOk(log).WriteTo(w)
	}
}

func (s *Server) getLog(userId, logId uint64) (Log, error) {
	// TODO: Error handling
	stmt := `SELECT timestamp,contents FROM logs WHERE id=? AND user_id=?`
	row := s.db.QueryRow(stmt, logId, userId)
	log := Log{Id: logId, UserId: userId}
	if err := row.Scan(&log.Timestamp, &log.Contents); err != nil {
		return Log{}, err
	}
	return log, nil
}

func (s *Server) NewLogHandler(w http.ResponseWriter, r *http.Request) {
	userId, ok := userIdFromJWT(r)
	if !ok {
		newRespErr(statusUA, "missing token").WriteTo(w)
		return
	}
	log := Log{}
	if err := json.NewDecoder(r.Body).Decode(&log); err != nil {
		// TODO: Handle errors
		newRespErr(statusBR, "invalid log object").WriteTo(w)
	}
	log.UserId = userId
	if log.Timestamp <= 0 {
		log.Timestamp = time.Now().Unix()
	}
	if err := s.newLog(&log); err != nil {
		newRespErr(statusISE, iseText).WriteTo(w)
		// TODO: log log?
		logpkg.Printf("Error creating log for ID %d: %v", userId, err)
	} else {
		newRespOk(log).WriteTo(w)
	}
}

func (s *Server) newLog(log *Log) error {
	res, err := s.db.Exec(
		`INSERT INTO logs(user_id,timestamp,contents) VALUES (?,?,?)`,
		log.UserId, log.Timestamp, log.Contents,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err == nil {
		log.Id = uint64(id)
	}
	return err
}

func (s *Server) DeleteLogHandler(w http.ResponseWriter, r *http.Request) {
	if userId, ok := userIdFromJWT(r); !ok {
		newRespErr(http.StatusUnauthorized, "invalid JWT").WriteTo(w)
	} else if logId, ok := idFromReq(r); !ok {
		newRespErr(statusBR, "invalid log id").WriteTo(w)
	} else if err := s.deleteLog(userId, logId); err != nil {
		status, errMsg := 0, ""
		if errors.Is(err, errUserNotExist) {
			status, errMsg = http.StatusUnauthorized, "user doesn't exist"
		} else if errors.Is(err, errLogNotExist) {
			status, errMsg = http.StatusNotFound, "log doesn't exist"
		} else {
			status, errMsg = statusISE, iseText
			logpkg.Printf("error deleting log for ID %d: %v", userId, err)
		}
		newRespErr(status, errMsg).WriteTo(w)
	} else {
		newRespOk(nil).WriteTo(w)
	}
}

func (s *Server) deleteLog(userId, logId uint64) error {
	_, err := s.db.Exec(
		`DELETE FROM logs WHERE id=? AND user_id=?`,
		logId, userId,
	)
	return err
}

/* Journals */

type Journal struct {
	Id     uint64 `json:"id,omitempty"`
	UserId uint64 `json:"userId,omitempty"`
	// The timestamp (day) the Journal is for
	//ForTimestamp int64 `json:"forTimestamp"`
	Timestamp int64  `json:"forTimestamp"`
	AddedAt   int64  `json:"addedAt,omitempty"`
	Contents  string `json:"contents,omitempty"`
	// Path to file
	path string
}

type GetJournalsOpts struct {
	Before int64
	After  int64

	AddedBefore int64
	AddedAfter  int64

	SortByTime   bool
	SortTimeDesc bool

	SortByAdded   bool
	SortAddedDesc bool
}

// Any error returned from here can be sent directly to the client without
// needing to be changed or logged
func parseGetJournalsOpts(r *http.Request) (GetJournalsOpts, error) {
	var err error
	opts, query := GetJournalsOpts{}, r.URL.Query()
	if beforeStr := query.Get("before"); beforeStr == "" {
	} else if opts.Before, err = strconv.ParseInt(beforeStr, 10, 64); err != nil {
		return opts, fmt.Errorf("invalid `before` value")
	} else if opts.Before < 0 {
		return opts, fmt.Errorf("`before` cannot be negative")
	}

	if afterStr := query.Get("after"); afterStr == "" {
	} else if opts.After, err = strconv.ParseInt(afterStr, 10, 64); err != nil {
		return opts, fmt.Errorf("invalid `after` value")
	} else if opts.After < 0 {
		return opts, fmt.Errorf("`after` cannot be negative")
	}

	if addedBeforeStr := query.Get("added_before"); addedBeforeStr == "" {
	} else if opts.AddedBefore, err = strconv.ParseInt(addedBeforeStr, 10, 64); err != nil {
		return opts, fmt.Errorf("invalid `added_before` value")
	} else if opts.AddedBefore < 0 {
		return opts, fmt.Errorf("`added_before` cannot be negative")
	}

	if addedAfterStr := query.Get("added_after"); addedAfterStr == "" {
	} else if opts.AddedAfter, err = strconv.ParseInt(addedAfterStr, 10, 64); err != nil {
		return opts, fmt.Errorf("invalid `added_after` value")
	} else if opts.AddedAfter < 0 {
		return opts, fmt.Errorf("`added_after` cannot be negative")
	}

	if sortTimeStr := query.Get("sort_time"); sortTimeStr == "" {
	} else if opts.SortByTime, err = strconv.ParseBool(sortTimeStr); err != nil {
		return opts, fmt.Errorf("invalid `sort_time` value")
	}

	if sortDescStr := query.Get("time_desc"); sortDescStr == "" {
	} else if opts.SortTimeDesc, err = strconv.ParseBool(sortDescStr); err != nil {
		return opts, fmt.Errorf("invalid `time_desc` value")
	}

	if sortAddedStr := query.Get("sort_added"); sortAddedStr == "" {
	} else if opts.SortByAdded, err = strconv.ParseBool(sortAddedStr); err != nil {
		return opts, fmt.Errorf("invalid `sort_added` value")
	}

	if sortDescStr := query.Get("added_desc"); sortDescStr == "" {
	} else if opts.SortAddedDesc, err = strconv.ParseBool(sortDescStr); err != nil {
		return opts, fmt.Errorf("invalid `added_desc` value")
	}
	return opts, nil
}

// The returned string, has a leading space (if there was something to add)
func (opts GetJournalsOpts) makeQuery() string {
	stmt := ""
	if opts.After != 0 {
		stmt += fmt.Sprint(` AND timestamp >= `, opts.After)
	}
	if opts.Before != 0 {
		stmt += fmt.Sprint(` AND timestamp <= `, opts.Before)
	}
	if opts.AddedAfter != 0 {
		stmt += fmt.Sprint(` AND added_at >= `, opts.AddedAfter)
	}
	if opts.AddedBefore != 0 {
		stmt += fmt.Sprint(` AND added_at <= `, opts.AddedBefore)
	}
	sorting := false
	if opts.SortByTime {
		sorting = true
		stmt += ` ORDER BY timestamp`
	}
	if opts.SortTimeDesc {
		if !sorting {
			sorting = true
			stmt += ` ORDER BY timestamp`
		}
		stmt += ` DESC`
	}
	if opts.SortByAdded {
		if !sorting {
			sorting = true
			stmt += ` ORDER BY added_at`
		} else {
			stmt += `, added_at`
		}
	}
	if opts.SortAddedDesc {
		if !sorting {
			sorting = true
			stmt += ` ORDER BY added_at`
		}
		stmt += ` DESC`
	}
	return stmt
}

func (s *Server) GetJournalsHandler(w http.ResponseWriter, r *http.Request) {
	if opts, err := parseGetJournalsOpts(r); err != nil {
	} else if userId, ok := userIdFromJWT(r); !ok {
		newRespErr(http.StatusUnauthorized, "invalid JWT").WriteTo(w)
	} else if journals, err := s.getJournals(userId, opts); err != nil {
		newResp(statusISE, journals, iseText)
		logpkg.Printf("error getting journals for ID %d: %v", userId, err)
	} else {
		newRespOk(journals).WriteTo(w)
	}
}

func (s *Server) getJournals(
	userId uint64, opts GetJournalsOpts,
) ([]Journal, error) {
	stmt := `SELECT id,timestamp,contents FROM journals WHERE user_id=?`

	rows, err := s.db.Query(stmt+opts.makeQuery(), userId)
	if err != nil {
		return nil, err
	}
	var journals []Journal
	for rows.Next() {
		journal := Journal{UserId: userId}
		if e := rows.Scan(
			&journal.Id, &journal.Timestamp, &journal.Contents,
		); e != nil {
			// Set to first error
			if err != nil {
				err = e
			}
		} else {
			journals = append(journals, journal)
		}
	}
	if err != nil && len(journals) == 0 {
		journals = nil
	}
	return journals, err
}

func (s *Server) GetJournalHandler(w http.ResponseWriter, r *http.Request) {
	if userId, ok := userIdFromJWT(r); !ok {
		newRespErr(http.StatusUnauthorized, "invalid JWT").WriteTo(w)
	} else if journalId, ok := idFromReq(r); !ok {
		newRespErr(statusBR, "invalid journal id").WriteTo(w)
	} else if journal, err := s.getJournal(userId, journalId); err != nil {
		status, errMsg := 0, ""
		if errors.Is(err, errUserNotExist) {
			status, errMsg = http.StatusUnauthorized, "user doesn't exist"
		} else if errors.Is(err, errJournalNotExist) {
			status, errMsg = http.StatusNotFound, "journal doesn't exist"
		} else {
			status, errMsg = statusISE, iseText
			logpkg.Printf("error getting journal for ID %d: %v", userId, err)
		}
		newRespErr(status, errMsg).WriteTo(w)
	} else if journal.Contents, err = s.getJournalContents(journal.path); err != nil {
		newRespErr(statusISE, iseText).WriteTo(w)
		logpkg.Printf("error getting journal contents for ID %d: %v", userId, err)
	} else {
		newRespOk(journal).WriteTo(w)
	}
}

func (s *Server) getJournal(userId, journalId uint64) (Journal, error) {
	// TODO: Error handling
	row := s.db.QueryRow(
		`SELECT timestamp,added_at,path FROM journals WHERE id=? AND user_id=?`,
		journalId, userId,
	)
	journal := Journal{Id: journalId, UserId: userId}
	err := row.Scan(&journal.Timestamp, &journal.AddedAt, &journal.path)
	if err != nil {
		return Journal{}, err
	}
	if journal.Contents, err = s.getJournalContents(journal.path); err != nil {
		return Journal{}, err
	}
	return journal, nil
}

// The path is the path relative to the journals directory
func (s *Server) getJournalContents(path string) (string, error) {
	path = filepath.Join(s.journalsDir, path)
	contents, err := os.ReadFile(path)
	return string(contents), err
}

func (s *Server) NewJournalHandler(w http.ResponseWriter, r *http.Request) {
	userId, ok := userIdFromJWT(r)
	if !ok {
		newRespErr(statusUA, "missing token").WriteTo(w)
		return
	}
	journal := Journal{}
	if journal.Contents == "" {
		newRespErr(statusBR, "empty journal contents").WriteTo(w)
	} else if err := json.NewDecoder(r.Body).Decode(&journal); err != nil {
		// TODO: Handle errors
		newRespErr(statusBR, "invalid journal object").WriteTo(w)
	}
	journal.UserId = userId
	if journal.Timestamp <= 0 {
		journal.Timestamp = time.Now().Unix()
	}
	if journal.AddedAt <= 0 {
		journal.AddedAt = time.Now().Unix()
	}
	if err := s.newJournal(&journal); err != nil {
		newRespErr(statusISE, iseText).WriteTo(w)
		// TODO: log journal?
		logpkg.Printf("Error creating journal for ID %d: %v", userId, err)
	} else if err = s.writeJournalContents(journal.path, journal.Contents); err != nil {
		newRespErr(statusISE, iseText).WriteTo(w)
		// TODO: log journal?
		logpkg.Printf("Error writing journal contents for ID %d: %v", userId, err)
	} else {
		// Don't send contents back
		journal.Contents = ""
		newRespOk(journal).WriteTo(w)
	}
}

// Returns the directory that holds the user's journals (not including
// Server.journalsDir).
func (s *Server) generateJournalsDirPath(userId uint64) string {
	return filepath.Join(
		strconv.FormatUint((userId+1)/1000*1000, 10),
		strconv.FormatUint(userId, 10),
	)
}

// Returns the path to a specific journal (not including Server.journalsDir).
func (s *Server) generateJournalPath(userId, journalId uint64) string {
	return filepath.Join(
		s.generateJournalsDirPath(userId),
		strconv.FormatUint(journalId, 10),
	)
}

func (s *Server) newJournal(journal *Journal) error {
	res, err := s.db.Exec(
		`INSERT INTO journals(user_id,timestamp,added_at,path) VALUES (?,?,?,?)`,
		journal.UserId, journal.Timestamp, journal.AddedAt, journal.path,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	journal.Id = uint64(id)
	journal.path = s.generateJournalPath(journal.UserId, journal.Id)
	_, err = s.db.Exec(
		`UPDATE journals SET path=? WHERE id=?`,
		journal.path, journal.Id,
	)
	// TODO: Return different (more specific) error?
	return err
}

func (s *Server) writeJournalContents(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0755)
}

func (s *Server) DeleteJournalHandler(w http.ResponseWriter, r *http.Request) {
	if userId, ok := userIdFromJWT(r); !ok {
		newRespErr(http.StatusUnauthorized, "invalid JWT").WriteTo(w)
	} else if journalId, ok := idFromReq(r); !ok {
		newRespErr(statusBR, "invalid journal id").WriteTo(w)
	} else if journal, err := s.getJournal(userId, journalId); err != nil {
		status, errMsg := 0, ""
		if errors.Is(err, errUserNotExist) {
			status, errMsg = http.StatusUnauthorized, "user doesn't exist"
		} else if errors.Is(err, errJournalNotExist) {
			status, errMsg = http.StatusNotFound, "journal doesn't exist"
		} else {
			status, errMsg = statusISE, iseText
			logpkg.Printf("error getting journal for ID %d: %v", userId, err)
		}
		newRespErr(status, errMsg).WriteTo(w)
	} else if err := s.deleteJournal(userId, journalId); err != nil {
		status, errMsg := 0, ""
		if errors.Is(err, errUserNotExist) {
			status, errMsg = http.StatusUnauthorized, "user doesn't exist"
		} else if errors.Is(err, errJournalNotExist) {
			status, errMsg = http.StatusNotFound, "journal doesn't exist"
		} else {
			status, errMsg = statusISE, iseText
			logpkg.Printf("error deleting journal for ID %d: %v", userId, err)
		}
		newRespErr(status, errMsg).WriteTo(w)
	} else if err := s.deleteJournalContents(journal.path); err != nil {
		newRespErr(statusISE, iseText).WriteTo(w)
		logpkg.Printf("error deleting journal contents for ID %d: %v", userId, err)
	} else {
		newRespOk(nil).WriteTo(w)
	}
}

func (s *Server) deleteJournal(userId, journalId uint64) error {
	_, err := s.db.Exec(
		`DELETE FROM journals WHERE id=? AND user_id=?`,
		journalId, userId,
	)
	if err != nil {
		return err
	}
	return os.Remove(
		filepath.Join(s.journalsDir, s.generateJournalPath(userId, journalId)),
	)
}

func (s *Server) deleteJournalContents(path string) error {
	return os.Remove(filepath.Join(s.journalsDir, path))
}

type Resp struct {
	Status int    `json:"status"`
	Data   any    `json:"data,omitempty"`
	Error  string `json:"error,omitempty"`
}

func newResp(status int, data any, errMsg string) *Resp {
	return &Resp{Status: status, Data: data, Error: errMsg}
}

func newRespOk(data any) *Resp {
	return &Resp{Status: 200, Data: data}
}

func newRespErr(status int, errMsg string) *Resp {
	return &Resp{Status: status, Error: errMsg}
}

func (resp *Resp) WriteTo(w io.Writer) (n int64, err error) {
	c := newCW(w)
	err = json.NewEncoder(c).Encode(resp)
	return int64(c.N()), err
}

type countWriter struct {
	w  io.Writer
	_n atomic.Uint64
	n  uint64
}

func newCW(w io.Writer) *countWriter {
	return &countWriter{w: w}
}

func (cw *countWriter) Write(b []byte) (n int, err error) {
	n, err = cw.w.Write(b)
	//cw.n.Add(uint64(n))
	cw.n += uint64(n)
	return n, err
}

func (cw *countWriter) N() uint64 {
	//return cw.n.Load()
	return cw.n
}

func containsHeaderValue(r *http.Request, key, val string) bool {
	return sort.StringSlice(r.Header.Values(key)).Search(val) != -1
}

func userIdFromJWT(r *http.Request) (uint64, bool) {
	if _, claims, err := jwtauth.FromContext(r.Context()); err != nil {
	} else if idStr, ok := claims["userId"].(string); !ok {
	} else if id, err := strconv.ParseUint(idStr, 10, 64); err != nil {
	} else {
		return id, true
	}
	return 0, false
}

func idFromReq(r *http.Request) (uint64, bool) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	return id, err == nil
}

func wantsJSON(r *http.Request) bool {
	return containsHeaderValue(r, "Accept", "application/json")
}

func wantsHTML(r *http.Request) bool {
	return containsHeaderValue(r, "Accept", "text/html")
}

func acceptsCookies(r *http.Request) bool {
	return r.URL.Query().Has("no_cookie")
}

func checkEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func hashPassword(pwd string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	return string(hashed), err
}

func checkPassword(pwd, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pwd)) != nil
}
