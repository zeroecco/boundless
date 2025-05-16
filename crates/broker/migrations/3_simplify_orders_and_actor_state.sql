-- Drop the old orders table if it exists
DROP TABLE IF EXISTS orders;

CREATE TABLE orders (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    image_id TEXT,
    input_id TEXT,
    proof_id TEXT,
    compressed_proof_id TEXT,
    error_msg TEXT
);
