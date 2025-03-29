-- +goose Up
ALTER TABLE users
ADD refresh_token TEXT NOT NULL DEFAULT 'tokenless';

-- +goose Down
ALTER TABLE users
DROP COLUMN refresh_token;