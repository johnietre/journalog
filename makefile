server:
	sqlite3 journalog.db ".read schema.sql"
	go build -o bin/journalog *.go
