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

-- name: UpdateUser :one
UPDATE users SET updated_at = NOW(), email = $2, hashed_password = $3 WHERE $1 = id
RETURNING *;

-- name: UpdateUserToChirpyRed :one
UPDATE users SET updated_at = NOW(), is_chirpy_red = TRUE WHERE $1 = id
RETURNING *;