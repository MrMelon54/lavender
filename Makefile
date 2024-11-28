SQL_SRC_DIR := database
SQL_FILES := $(wildcard $(SQL_SRC_DIR)/{migrations,queries}/*.sql)

.PHONY: all sqlc astro build

all: sqlc astro

sqlc: $(SQL_FILES)
	sqlc generate

astro:
	cd web && yarn build

build: sqlc
	go build ./cmd/lavender
