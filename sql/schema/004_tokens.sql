-- +goose Up
ALTER TABLE users
ADD token TEXT NOT NULL DEFAULT 'tokenless';

-- +goose Down
ALTER TABLE users
DROP COLUMN token;