-- name: CreateChirp :one
INSERT INTO chirps (
    id, created_at, updated_at, body, user_id
) VALUES (
    gen_random_uuid(), NOW(), NOW(), $1, $2
)
RETURNING *;

-- name: DeleteChirps :exec
DELETE FROM chirps;

-- name: GetChirps :many
SELECT * FROM chirps ORDER BY (CASE WHEN $1 = 'DESC' THEN created_at END) DESC, created_at;

-- name: GetUserChirps :many
SELECT * FROM chirps WHERE user_id = $1 ORDER BY (CASE WHEN $2 = 'DESC' THEN created_at END) DESC, created_at;

-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1;

-- name: GetChirp :one
SELECT * FROM chirps WHERE id = $1;