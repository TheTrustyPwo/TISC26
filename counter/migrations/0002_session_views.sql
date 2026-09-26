CREATE TABLE challenge_views (
  slug TEXT NOT NULL,
  session_id TEXT NOT NULL,
  PRIMARY KEY (slug, session_id)
);

CREATE TRIGGER challenge_view_added AFTER INSERT ON challenge_views
BEGIN
  INSERT INTO challenge_counts (slug, views) VALUES (NEW.slug, 1)
  ON CONFLICT(slug) DO UPDATE SET views = views + 1;
END;
