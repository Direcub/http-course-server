-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: Reset :exec
DELETE FROM users;

-- name: FindUserbyEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserByToken :one
SELECT * FROM users
WHERE token = $1;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: UpdateCredentials :exec
UPDATE users
SET email = $1, hashed_password = $2
WHERE id = $3;

-- name: AddJWT :exec
UPDATE users
SET token = $1
WHERE id = $2;

-- name: MakeRed :exec
UPDATE users
SET is_chirpy_red = true
WHERE id = $1;