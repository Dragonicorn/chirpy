-- name: DeleteUsers :exec
DELETE FROM users;

-- name: CreateUser :one
INSERT INTO users (
    id, created_at, updated_at, email, hashed_password
) VALUES (
    gen_random_uuid(), NOW(), NOW(), $1, $2
)
RETURNING *;

-- name: GetUser :one
SELECT * FROM users WHERE $1 = email;