CREATE TABLE challenge_counts (
  slug TEXT PRIMARY KEY,
  views INTEGER NOT NULL DEFAULT 0 CHECK (views >= 0),
  likes INTEGER NOT NULL DEFAULT 0 CHECK (likes >= 0)
);

CREATE TABLE challenge_likes (
  slug TEXT NOT NULL,
  voter_id TEXT NOT NULL,
  PRIMARY KEY (slug, voter_id)
);

CREATE TRIGGER challenge_like_added AFTER INSERT ON challenge_likes
BEGIN
  INSERT INTO challenge_counts (slug, likes) VALUES (NEW.slug, 1)
  ON CONFLICT(slug) DO UPDATE SET likes = likes + 1;
END;

CREATE TRIGGER challenge_like_removed AFTER DELETE ON challenge_likes
BEGIN
  UPDATE challenge_counts SET likes = likes - 1 WHERE slug = OLD.slug;
END;
