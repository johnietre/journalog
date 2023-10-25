server:
	sqlite3 journalog.db ".read schema.sql"
	go build -o bin/journalog *.go

test-server:
	sqlite3 test.db ".read schema.sql"
	go build -o bin/journalog *.go --db=test.db --journals-dir=test-journals
	JOURNALOG_JWT_SECRET=test-jwt bin/journalog
